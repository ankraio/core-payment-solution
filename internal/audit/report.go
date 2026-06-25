package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
)

type Report struct {
	SessionID     string        `json:"session_id"`
	SourceIP      string        `json:"source_ip"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	DurationLabel string        `json:"duration"`
	MaxSeverity   string        `json:"max_severity"`
	Machines      []string      `json:"machines_touched"`
	Services      []string      `json:"services_touched"`
	Signatures    []string      `json:"signatures"`
	EventCount    int           `json:"event_count"`
	Route         []RouteHop    `json:"route"`
	Timeline      []event.Event `json:"timeline"`
}

type RouteHop struct {
	Order       int       `json:"order"`
	Machine     string    `json:"machine"`
	Service     string    `json:"service"`
	EnteredAt   time.Time `json:"entered_at"`
	Actions     int       `json:"actions"`
	TopSeverity string    `json:"top_severity"`
}

func BuildReport(sessionID, sourceIP string, events []event.Event) Report {
	report := Report{
		SessionID:  sessionID,
		SourceIP:   sourceIP,
		EventCount: len(events),
		Timeline:   events,
	}
	if len(events) == 0 {
		return report
	}
	report.FirstSeen = events[0].OccurredAt
	report.LastSeen = events[len(events)-1].OccurredAt
	report.DurationLabel = report.LastSeen.Sub(report.FirstSeen).Round(time.Second).String()

	machineSet := map[string]struct{}{}
	serviceSet := map[string]struct{}{}
	signatureSet := map[string]struct{}{}
	maxRank := -1

	var hops []RouteHop
	currentMachine := ""
	currentService := ""
	var currentHop *RouteHop

	for _, item := range events {
		if item.Machine != "" {
			machineSet[item.Machine] = struct{}{}
		}
		if item.Service != "" {
			serviceSet[item.Service] = struct{}{}
		}
		if item.Signature != "" {
			signatureSet[item.Signature] = struct{}{}
		}
		if rank := event.SeverityRank(item.Severity); rank > maxRank {
			maxRank = rank
			report.MaxSeverity = string(item.Severity)
		}
		if item.Machine != currentMachine || item.Service != currentService {
			if currentHop != nil {
				hops = append(hops, *currentHop)
			}
			currentMachine = item.Machine
			currentService = item.Service
			currentHop = &RouteHop{
				Order:       len(hops) + 1,
				Machine:     item.Machine,
				Service:     item.Service,
				EnteredAt:   item.OccurredAt,
				TopSeverity: string(item.Severity),
			}
		}
		if currentHop != nil {
			currentHop.Actions++
			if event.SeverityRank(item.Severity) > event.SeverityRank(event.Severity(currentHop.TopSeverity)) {
				currentHop.TopSeverity = string(item.Severity)
			}
		}
	}
	if currentHop != nil {
		hops = append(hops, *currentHop)
	}
	report.Route = hops
	report.Machines = keys(machineSet)
	report.Services = keys(serviceSet)
	report.Signatures = keys(signatureSet)
	return report
}

func (report Report) JSON() ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func (report Report) Markdown() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Intrusion Report %s\n\n", report.SessionID)
	fmt.Fprintf(&builder, "- Source IP: `%s`\n", report.SourceIP)
	fmt.Fprintf(&builder, "- First seen: %s\n", report.FirstSeen.Format(time.RFC3339))
	fmt.Fprintf(&builder, "- Last seen: %s\n", report.LastSeen.Format(time.RFC3339))
	fmt.Fprintf(&builder, "- Duration: %s\n", report.DurationLabel)
	fmt.Fprintf(&builder, "- Max severity: **%s**\n", report.MaxSeverity)
	fmt.Fprintf(&builder, "- Machines touched: %s\n", strings.Join(report.Machines, ", "))
	fmt.Fprintf(&builder, "- Services touched: %s\n", strings.Join(report.Services, ", "))
	fmt.Fprintf(&builder, "- Total events: %d\n\n", report.EventCount)

	if len(report.Signatures) > 0 {
		builder.WriteString("## Triggered signatures\n\n")
		for _, signature := range report.Signatures {
			fmt.Fprintf(&builder, "- `%s`\n", signature)
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Attack route\n\n")
	for _, hop := range report.Route {
		fmt.Fprintf(&builder, "%d. **%s** via `%s` at %s - %d actions (max %s)\n",
			hop.Order, orDash(hop.Machine), orDash(hop.Service),
			hop.EnteredAt.Format("15:04:05"), hop.Actions, hop.TopSeverity)
	}
	builder.WriteString("\n## Full timeline\n\n")
	for _, item := range report.Timeline {
		line := fmt.Sprintf("- %s [%s] %s/%s %s: %s",
			item.OccurredAt.Format("15:04:05"), item.Severity, item.Machine,
			item.Service, item.Kind, item.Summary)
		if item.Signature != "" {
			line += fmt.Sprintf(" (`%s`)", item.Signature)
		}
		builder.WriteString(line + "\n")
	}
	return builder.String()
}

func keys(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	return result
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
