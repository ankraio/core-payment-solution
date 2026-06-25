package detect

import (
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/session"
)

type Finding struct {
	Severity  event.Severity
	Title     string
	Detail    string
	Signature string
	SourceIP  string
	SessionID string
	Kind      event.Kind
}

type Engine struct {
	settings config.DetectionConfig
	mutex    sync.Mutex
	ports    map[string]*slidingCounter
	auth     map[string]*slidingCounter
}

func NewEngine(settings config.DetectionConfig) *Engine {
	return &Engine{
		settings: settings,
		ports:    make(map[string]*slidingCounter),
		auth:     make(map[string]*slidingCounter),
	}
}

func (engine *Engine) Evaluate(item event.Event, observation session.Observation) []Finding {
	findings := make([]Finding, 0, 2)

	if item.Kind == event.KindExploitAttempt {
		findings = append(findings, Finding{
			Severity:  maxSeverity(item.Severity, event.SeverityHigh),
			Title:     "Exploit attempt",
			Detail:    item.Summary,
			Signature: item.Signature,
			SourceIP:  item.SourceIP,
			SessionID: observation.State.SessionID,
			Kind:      event.KindExploitAttempt,
		})
	}

	if item.Kind == event.KindSecretAccess {
		findings = append(findings, Finding{
			Severity:  maxSeverity(item.Severity, event.SeverityHigh),
			Title:     "Sensitive data access",
			Detail:    item.Summary,
			Signature: item.Signature,
			SourceIP:  item.SourceIP,
			SessionID: observation.State.SessionID,
			Kind:      event.KindSecretAccess,
		})
	}

	if engine.registerPort(item) {
		findings = append(findings, Finding{
			Severity:  event.SeverityMedium,
			Title:     "Port scan / service sweep",
			Detail:    "multiple distinct services probed in a short window",
			Signature: "recon.port_scan",
			SourceIP:  item.SourceIP,
			SessionID: observation.State.SessionID,
			Kind:      event.KindScan,
		})
	}

	if item.Kind == event.KindAuthAttempt && engine.registerAuth(item) {
		findings = append(findings, Finding{
			Severity:  event.SeverityMedium,
			Title:     "Credential brute force",
			Detail:    "repeated authentication attempts",
			Signature: "credential_access.brute_force",
			SourceIP:  item.SourceIP,
			SessionID: observation.State.SessionID,
			Kind:      event.KindAuthAttempt,
		})
	}

	if observation.NewMachine && observation.DistinctMachines >= engine.settings.LateralMovementMinimum {
		findings = append(findings, Finding{
			Severity:  event.SeverityHigh,
			Title:     "Lateral movement",
			Detail:    "attacker active across multiple machines",
			Signature: "lateral_movement.multi_host",
			SourceIP:  item.SourceIP,
			SessionID: observation.State.SessionID,
			Kind:      event.KindLateralMovement,
		})
	}

	return findings
}

func (engine *Engine) registerPort(item event.Event) bool {
	if item.DestPort == 0 {
		return false
	}
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	counter, exists := engine.ports[item.SourceIP]
	if !exists {
		counter = newSlidingCounter(engine.settings.PortScanWindow.Std())
		engine.ports[item.SourceIP] = counter
	}
	distinct := counter.addDistinct(item.DestPort, item.OccurredAt)
	return distinct == engine.settings.PortScanDistinctPorts
}

func (engine *Engine) registerAuth(item event.Event) bool {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	counter, exists := engine.auth[item.SourceIP]
	if !exists {
		counter = newSlidingCounter(engine.settings.BruteForceWindow.Std())
		engine.auth[item.SourceIP] = counter
	}
	total := counter.increment(item.OccurredAt)
	return total == engine.settings.BruteForceAttempts
}

func maxSeverity(left, right event.Severity) event.Severity {
	if event.SeverityRank(left) >= event.SeverityRank(right) {
		return left
	}
	return right
}

type slidingCounter struct {
	window     time.Duration
	timestamps []time.Time
	ports      map[int]time.Time
}

func newSlidingCounter(window time.Duration) *slidingCounter {
	return &slidingCounter{window: window, ports: make(map[int]time.Time)}
}

func (counter *slidingCounter) increment(now time.Time) int {
	counter.timestamps = append(counter.timestamps, now)
	counter.evict(now)
	return len(counter.timestamps)
}

func (counter *slidingCounter) addDistinct(port int, now time.Time) int {
	counter.ports[port] = now
	for existingPort, seenAt := range counter.ports {
		if now.Sub(seenAt) > counter.window {
			delete(counter.ports, existingPort)
		}
	}
	return len(counter.ports)
}

func (counter *slidingCounter) evict(now time.Time) {
	cutoff := 0
	for index, timestamp := range counter.timestamps {
		if now.Sub(timestamp) <= counter.window {
			cutoff = index
			break
		}
		cutoff = index + 1
	}
	counter.timestamps = counter.timestamps[cutoff:]
}
