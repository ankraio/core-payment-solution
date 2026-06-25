package collector

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/ankraio/core-payment-solution/internal/alarm"
	"github.com/ankraio/core-payment-solution/internal/audit"
	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/detect"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/log"
	"github.com/ankraio/core-payment-solution/internal/session"
	"github.com/ankraio/core-payment-solution/internal/slack"
	"github.com/ankraio/core-payment-solution/internal/store"
)

type Collector struct {
	settings  config.Config
	store     *store.Store
	sessions  *session.Manager
	detection *detect.Engine
	alarms    *alarm.Manager
	notifier  *slack.Notifier
	logger    *log.Logger
	reportDir string
}

func New(settings config.Config) (*Collector, error) {
	if makeError := os.MkdirAll(settings.Collector.DataDirectory, 0o700); makeError != nil {
		return nil, makeError
	}
	reportDir := filepath.Join(settings.Collector.DataDirectory, "reports")
	if makeError := os.MkdirAll(reportDir, 0o700); makeError != nil {
		return nil, makeError
	}
	dataStore, openError := store.Open(filepath.Join(settings.Collector.DataDirectory, "honeypot.db"))
	if openError != nil {
		return nil, openError
	}
	return &Collector{
		settings:  settings,
		store:     dataStore,
		sessions:  session.NewManager(settings.Detection.SessionIdleTimeout.Std()),
		detection: detect.NewEngine(settings.Detection),
		alarms:    alarm.NewManager(settings.Alarm),
		notifier:  slack.NewNotifier(settings.Slack),
		logger:    log.New("collector"),
		reportDir: reportDir,
	}, nil
}

func (collector *Collector) Store() *store.Store         { return collector.store }
func (collector *Collector) Sessions() *session.Manager { return collector.sessions }

func (collector *Collector) Ingest(events []event.Event) {
	runContext := context.Background()
	for _, item := range events {
		observation := collector.sessions.Observe(item)
		item.SessionID = observation.State.SessionID
		if storeError := collector.store.InsertEvent(runContext, item); storeError != nil {
			collector.logger.Error("event persist failed", "error", storeError)
		}
		collector.persistSession(runContext, observation)
		for _, finding := range collector.detection.Evaluate(item, observation) {
			if raised, fired := collector.alarms.Consider(finding, item.OccurredAt); fired {
				collector.logger.Warn("alarm raised",
					"title", raised.Title, "severity", raised.Severity,
					"source", raised.SourceIP, "signature", raised.Signature)
				collector.notifier.NotifyAlarm(runContext, raised)
			}
		}
	}
}

func (collector *Collector) persistSession(runContext context.Context, observation session.Observation) {
	state := observation.State
	record := store.SessionRecord{
		ID:          state.SessionID,
		SourceIP:    state.SourceIP,
		FirstSeen:   state.FirstSeen,
		LastSeen:    state.LastSeen,
		Machines:    state.MachineList(),
		Services:    state.ServiceList(),
		MaxSeverity: string(state.MaxSeverity),
		EventCount:  len(state.Steps),
		Reported:    state.Reported,
	}
	if upsertError := collector.store.UpsertSession(runContext, record); upsertError != nil {
		collector.logger.Error("session persist failed", "error", upsertError)
	}
}

func (collector *Collector) RunReportLoop(runContext context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-runContext.Done():
			return
		case <-ticker.C:
			collector.flushReports(runContext)
		}
	}
}

func (collector *Collector) flushReports(runContext context.Context) {
	due := collector.sessions.IdleUnreported(time.Now().UTC(), collector.settings.Alarm.ReportAfterIdle.Std())
	for _, state := range due {
		collector.emitReport(runContext, state.SessionID, state.SourceIP)
	}
}

func (collector *Collector) emitReport(runContext context.Context, sessionID, sourceIP string) {
	events, queryError := collector.store.EventsBySession(runContext, sessionID)
	if queryError != nil {
		collector.logger.Error("report query failed", "error", queryError)
		return
	}
	report := audit.BuildReport(sessionID, sourceIP, events)
	collector.writeReportArtifacts(report)
	collector.notifier.NotifyReport(runContext, report)
	if markError := collector.store.MarkReported(runContext, sessionID); markError != nil {
		collector.logger.Error("mark reported failed", "error", markError)
	}
	collector.logger.Info("intrusion report emitted", "session", sessionID, "source", sourceIP, "events", report.EventCount)
}

func (collector *Collector) BuildReport(runContext context.Context, sessionID, sourceIP string) (audit.Report, error) {
	events, queryError := collector.store.EventsBySession(runContext, sessionID)
	if queryError != nil {
		return audit.Report{}, queryError
	}
	return audit.BuildReport(sessionID, sourceIP, events), nil
}

func (collector *Collector) writeReportArtifacts(report audit.Report) {
	jsonBytes, marshalError := report.JSON()
	if marshalError == nil {
		_ = os.WriteFile(filepath.Join(collector.reportDir, report.SessionID+".json"), jsonBytes, 0o600)
	}
	_ = os.WriteFile(filepath.Join(collector.reportDir, report.SessionID+".md"), []byte(report.Markdown()), 0o600)
}

func (collector *Collector) Close() error {
	return collector.store.Close()
}
