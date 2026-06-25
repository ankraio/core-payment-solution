package alarm

import (
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/detect"
	"github.com/ankraio/core-payment-solution/internal/event"
)

type Alarm struct {
	RaisedAt  time.Time
	Severity  event.Severity
	Title     string
	Detail    string
	Signature string
	SourceIP  string
	SessionID string
}

type Manager struct {
	minimumRank int
	debounce    time.Duration
	mutex       sync.Mutex
	lastFired   map[string]time.Time
}

func NewManager(settings config.AlarmConfig) *Manager {
	minimum := event.Severity(settings.MinimumSeverity)
	return &Manager{
		minimumRank: event.SeverityRank(minimum),
		debounce:    settings.DebounceInterval.Std(),
		lastFired:   make(map[string]time.Time),
	}
}

func (manager *Manager) Consider(finding detect.Finding, now time.Time) (Alarm, bool) {
	if event.SeverityRank(finding.Severity) < manager.minimumRank {
		return Alarm{}, false
	}
	key := finding.SourceIP + "|" + finding.Signature
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if previous, exists := manager.lastFired[key]; exists {
		if now.Sub(previous) < manager.debounce {
			return Alarm{}, false
		}
	}
	manager.lastFired[key] = now
	return Alarm{
		RaisedAt:  now,
		Severity:  finding.Severity,
		Title:     finding.Title,
		Detail:    finding.Detail,
		Signature: finding.Signature,
		SourceIP:  finding.SourceIP,
		SessionID: finding.SessionID,
	}, true
}
