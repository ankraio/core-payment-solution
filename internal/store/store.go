package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
	_ "modernc.org/sqlite"
)

type Store struct {
	database *sql.DB
}

func Open(path string) (*Store, error) {
	database, openError := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if openError != nil {
		return nil, openError
	}
	database.SetMaxOpenConns(1)
	store := &Store{database: database}
	if migrateError := store.migrate(); migrateError != nil {
		return nil, migrateError
	}
	return store, nil
}

func (store *Store) Close() error {
	return store.database.Close()
}

func (store *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS events (
	id TEXT PRIMARY KEY,
	occurred_at TIMESTAMP NOT NULL,
	service TEXT NOT NULL,
	machine TEXT NOT NULL,
	kind TEXT NOT NULL,
	severity TEXT NOT NULL,
	source_ip TEXT NOT NULL,
	source_port INTEGER,
	destination_ip TEXT,
	destination_port INTEGER,
	session_id TEXT,
	summary TEXT,
	signature TEXT,
	payload TEXT,
	attributes TEXT
);
CREATE INDEX IF NOT EXISTS index_events_source ON events(source_ip);
CREATE INDEX IF NOT EXISTS index_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS index_events_time ON events(occurred_at);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	source_ip TEXT NOT NULL,
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL,
	machines TEXT,
	services TEXT,
	max_severity TEXT,
	event_count INTEGER,
	reported INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS index_sessions_source ON sessions(source_ip);
`
	_, executeError := store.database.Exec(schema)
	return executeError
}

func (store *Store) InsertEvent(runContext context.Context, item event.Event) error {
	attributesJSON, marshalError := json.Marshal(item.Attributes)
	if marshalError != nil {
		return marshalError
	}
	_, executeError := store.database.ExecContext(runContext, `
INSERT OR IGNORE INTO events
(id, occurred_at, service, machine, kind, severity, source_ip, source_port,
 destination_ip, destination_port, session_id, summary, signature, payload, attributes)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.ID, item.OccurredAt, item.Service, item.Machine, string(item.Kind),
		string(item.Severity), item.SourceIP, item.SourcePort, item.DestinationIP,
		item.DestPort, item.SessionID, item.Summary, item.Signature, item.Payload,
		string(attributesJSON))
	return executeError
}

func (store *Store) EventsBySession(runContext context.Context, sessionID string) ([]event.Event, error) {
	rows, queryError := store.database.QueryContext(runContext, `
SELECT id, occurred_at, service, machine, kind, severity, source_ip, source_port,
       destination_ip, destination_port, session_id, summary, signature, payload, attributes
FROM events WHERE session_id = ? ORDER BY occurred_at ASC`, sessionID)
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (store *Store) EventsBySource(runContext context.Context, sourceIP string) ([]event.Event, error) {
	rows, queryError := store.database.QueryContext(runContext, `
SELECT id, occurred_at, service, machine, kind, severity, source_ip, source_port,
       destination_ip, destination_port, session_id, summary, signature, payload, attributes
FROM events WHERE source_ip = ? ORDER BY occurred_at ASC`, sourceIP)
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (store *Store) RecentEvents(runContext context.Context, limit int) ([]event.Event, error) {
	rows, queryError := store.database.QueryContext(runContext, `
SELECT id, occurred_at, service, machine, kind, severity, source_ip, source_port,
       destination_ip, destination_port, session_id, summary, signature, payload, attributes
FROM events ORDER BY occurred_at DESC LIMIT ?`, limit)
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]event.Event, error) {
	collected := make([]event.Event, 0)
	for rows.Next() {
		var item event.Event
		var kind, severity, attributesJSON string
		var occurredAt time.Time
		if scanError := rows.Scan(&item.ID, &occurredAt, &item.Service, &item.Machine,
			&kind, &severity, &item.SourceIP, &item.SourcePort, &item.DestinationIP,
			&item.DestPort, &item.SessionID, &item.Summary, &item.Signature,
			&item.Payload, &attributesJSON); scanError != nil {
			return nil, scanError
		}
		item.OccurredAt = occurredAt
		item.Kind = event.Kind(kind)
		item.Severity = event.Severity(severity)
		if attributesJSON != "" {
			_ = json.Unmarshal([]byte(attributesJSON), &item.Attributes)
		}
		collected = append(collected, item)
	}
	return collected, rows.Err()
}

type SessionRecord struct {
	ID          string    `json:"id"`
	SourceIP    string    `json:"source_ip"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Machines    []string  `json:"machines"`
	Services    []string  `json:"services"`
	MaxSeverity string    `json:"max_severity"`
	EventCount  int       `json:"event_count"`
	Reported    bool      `json:"reported"`
}

func (store *Store) UpsertSession(runContext context.Context, record SessionRecord) error {
	machinesJSON, _ := json.Marshal(record.Machines)
	servicesJSON, _ := json.Marshal(record.Services)
	_, executeError := store.database.ExecContext(runContext, `
INSERT INTO sessions (id, source_ip, first_seen, last_seen, machines, services, max_severity, event_count, reported)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
	last_seen=excluded.last_seen,
	machines=excluded.machines,
	services=excluded.services,
	max_severity=excluded.max_severity,
	event_count=excluded.event_count,
	reported=excluded.reported`,
		record.ID, record.SourceIP, record.FirstSeen, record.LastSeen,
		string(machinesJSON), string(servicesJSON), record.MaxSeverity,
		record.EventCount, boolToInt(record.Reported))
	return executeError
}

func (store *Store) MarkReported(runContext context.Context, sessionID string) error {
	_, executeError := store.database.ExecContext(runContext,
		`UPDATE sessions SET reported = 1 WHERE id = ?`, sessionID)
	return executeError
}

func (store *Store) ListSessions(runContext context.Context, limit int) ([]SessionRecord, error) {
	rows, queryError := store.database.QueryContext(runContext, `
SELECT id, source_ip, first_seen, last_seen, machines, services, max_severity, event_count, reported
FROM sessions ORDER BY last_seen DESC LIMIT ?`, limit)
	if queryError != nil {
		return nil, queryError
	}
	defer rows.Close()
	records := make([]SessionRecord, 0)
	for rows.Next() {
		var record SessionRecord
		var machinesJSON, servicesJSON string
		var reported int
		if scanError := rows.Scan(&record.ID, &record.SourceIP, &record.FirstSeen,
			&record.LastSeen, &machinesJSON, &servicesJSON, &record.MaxSeverity,
			&record.EventCount, &reported); scanError != nil {
			return nil, scanError
		}
		_ = json.Unmarshal([]byte(machinesJSON), &record.Machines)
		_ = json.Unmarshal([]byte(servicesJSON), &record.Services)
		record.Reported = reported != 0
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *Store) CountEvents(runContext context.Context) (int, error) {
	row := store.database.QueryRowContext(runContext, `SELECT COUNT(*) FROM events`)
	var total int
	scanError := row.Scan(&total)
	return total, scanError
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (store *Store) Ping(runContext context.Context) error {
	return store.database.PingContext(runContext)
}
