package session

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
)

type Step struct {
	OccurredAt time.Time      `json:"occurred_at"`
	Machine    string         `json:"machine"`
	Service    string         `json:"service"`
	Kind       event.Kind     `json:"kind"`
	Severity   event.Severity `json:"severity"`
	Summary    string         `json:"summary"`
	Signature  string         `json:"signature,omitempty"`
}

type State struct {
	SessionID   string
	SourceIP    string
	FirstSeen   time.Time
	LastSeen    time.Time
	Machines    map[string]struct{}
	Services    map[string]struct{}
	MaxSeverity event.Severity
	Steps       []Step
	Reported    bool
}

type Manager struct {
	mutex       sync.Mutex
	states      map[string]*State
	idleTimeout time.Duration
}

func NewManager(idleTimeout time.Duration) *Manager {
	if idleTimeout <= 0 {
		idleTimeout = 10 * time.Minute
	}
	return &Manager{
		states:      make(map[string]*State),
		idleTimeout: idleTimeout,
	}
}

type Observation struct {
	State            *State
	NewMachine       bool
	DistinctMachines int
}

func (manager *Manager) Observe(item event.Event) Observation {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.states[item.SourceIP]
	if !exists || item.OccurredAt.Sub(state.LastSeen) > manager.idleTimeout {
		state = &State{
			SessionID: deriveSessionID(item.SourceIP, item.OccurredAt),
			SourceIP:  item.SourceIP,
			FirstSeen: item.OccurredAt,
			Machines:  make(map[string]struct{}),
			Services:  make(map[string]struct{}),
		}
		manager.states[item.SourceIP] = state
	}

	_, machineSeen := state.Machines[item.Machine]
	newMachine := !machineSeen && item.Machine != ""

	state.LastSeen = item.OccurredAt
	if item.Machine != "" {
		state.Machines[item.Machine] = struct{}{}
	}
	if item.Service != "" {
		state.Services[item.Service] = struct{}{}
	}
	if event.SeverityRank(item.Severity) > event.SeverityRank(state.MaxSeverity) {
		state.MaxSeverity = item.Severity
	}
	state.Steps = append(state.Steps, Step{
		OccurredAt: item.OccurredAt,
		Machine:    item.Machine,
		Service:    item.Service,
		Kind:       item.Kind,
		Severity:   item.Severity,
		Summary:    item.Summary,
		Signature:  item.Signature,
	})

	return Observation{State: state, NewMachine: newMachine, DistinctMachines: len(state.Machines)}
}

func (manager *Manager) IdleUnreported(now time.Time, idle time.Duration) []*State {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	var due []*State
	for _, state := range manager.states {
		if !state.Reported && now.Sub(state.LastSeen) >= idle && len(state.Steps) > 0 {
			state.Reported = true
			due = append(due, state)
		}
	}
	return due
}

func (manager *Manager) Snapshot() []State {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	snapshot := make([]State, 0, len(manager.states))
	for _, state := range manager.states {
		snapshot = append(snapshot, *state)
	}
	return snapshot
}

func (state *State) SessionIDValue() string { return state.SessionID }

func (state *State) MachineList() []string { return sortedKeys(state.Machines) }

func (state *State) ServiceList() []string { return sortedKeys(state.Services) }

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func deriveSessionID(sourceIP string, occurredAt time.Time) string {
	digest := sha1.Sum([]byte(fmt.Sprintf("%s-%d", sourceIP, occurredAt.Truncate(time.Hour).Unix())))
	return "sess_" + hex.EncodeToString(digest[:8])
}

func RemoteIP(remoteAddress string) string {
	host, _, splitError := net.SplitHostPort(remoteAddress)
	if splitError != nil {
		return remoteAddress
	}
	return host
}

func ClientIP(request *http.Request, trustForwardedFor bool) string {
	if trustForwardedFor {
		forwarded := request.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			parts := strings.Split(forwarded, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return RemoteIP(request.RemoteAddr)
}
