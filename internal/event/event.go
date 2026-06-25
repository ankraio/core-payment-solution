package event

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Kind string

const (
	KindConnection      Kind = "connection"
	KindAuthAttempt     Kind = "auth_attempt"
	KindAuthSuccess     Kind = "auth_success"
	KindCommand         Kind = "command"
	KindHTTPRequest     Kind = "http_request"
	KindExploitAttempt  Kind = "exploit_attempt"
	KindSecretAccess    Kind = "secret_access"
	KindFileAccess      Kind = "file_access"
	KindScan            Kind = "scan"
	KindLateralMovement Kind = "lateral_movement"
	KindDataExfil       Kind = "data_exfiltration"
)

type Event struct {
	ID            string         `json:"id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Service       string         `json:"service"`
	Machine       string         `json:"machine"`
	Kind          Kind           `json:"kind"`
	Severity      Severity       `json:"severity"`
	SourceIP      string         `json:"source_ip"`
	SourcePort    int            `json:"source_port"`
	DestinationIP string         `json:"destination_ip"`
	DestPort      int            `json:"destination_port"`
	SessionID     string         `json:"session_id"`
	Summary       string         `json:"summary"`
	Signature     string         `json:"signature,omitempty"`
	Payload       string         `json:"payload,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type Batch struct {
	Events []Event `json:"events"`
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}
