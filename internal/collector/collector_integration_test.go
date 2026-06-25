package collector_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ankraio/core-payment-solution/internal/audit"
	"github.com/ankraio/core-payment-solution/internal/collector"
	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/transport"
)

func TestEndToEndAttackRouteReport(t *testing.T) {
	settings := config.Default()
	settings.Collector.DataDirectory = t.TempDir()
	settings.Slack.Enabled = false
	settings.Detection.PortScanDistinctPorts = 5
	settings.Detection.BruteForceAttempts = 3
	settings.Detection.LateralMovementMinimum = 2

	brain, newError := collector.New(settings)
	if newError != nil {
		t.Fatalf("collector init: %v", newError)
	}
	defer brain.Close()

	ingestServer := httptest.NewServer(transport.IngestHandler{OnBatch: brain.Ingest})
	defer ingestServer.Close()
	dashboardServer := httptest.NewServer(collector.NewDashboard(brain, "test-token").Handler())
	defer dashboardServer.Close()

	client := transport.NewClient(transport.ClientOptions{
		CollectorURL: ingestServer.URL,
		Machine:      "unset",
		Service:      "test",
		SpoolDir:     t.TempDir(),
	})

	attacker := "203.0.113.66"
	now := time.Now().UTC()

	for portIndex, port := range []int{22, 80, 443, 6379, 6443, 8080, 8000} {
		client.Emit(event.Event{
			OccurredAt: now.Add(time.Duration(portIndex) * time.Second),
			Machine:    "gateway-01", Service: "recon", Kind: event.KindConnection,
			Severity: event.SeverityInfo, SourceIP: attacker, DestPort: port,
			Summary: "probe",
		})
	}
	for attempt := 0; attempt < 4; attempt++ {
		client.Emit(event.Event{
			OccurredAt: now.Add(time.Duration(10+attempt) * time.Second),
			Machine:    "legacy-tomcat-01", Service: "tomcat", Kind: event.KindAuthAttempt,
			Severity: event.SeverityMedium, SourceIP: attacker, DestPort: 8080,
			Summary: "tomcat manager login", Signature: "credential_access.tomcat_manager_bruteforce",
		})
	}
	client.Emit(event.Event{
		OccurredAt: now.Add(20 * time.Second),
		Machine:    "legacy-tomcat-01", Service: "tomcat", Kind: event.KindExploitAttempt,
		Severity: event.SeverityCritical, SourceIP: attacker, DestPort: 8080,
		Summary: "JSP upload", Signature: "exploit.tomcat_put_jsp",
	})
	client.Emit(event.Event{
		OccurredAt: now.Add(30 * time.Second),
		Machine:    "k8s-control-01", Service: "kube-apiserver", Kind: event.KindSecretAccess,
		Severity: event.SeverityCritical, SourceIP: attacker, DestPort: 6443,
		Summary: "k8s secrets", Signature: "k8s.anonymous_secret_access",
	})

	client.Close()

	report := waitForReport(t, dashboardServer.URL, attacker)
	if len(report.Machines) < 2 {
		t.Fatalf("expected lateral movement across >=2 machines, got %v", report.Machines)
	}
	if report.MaxSeverity != string(event.SeverityCritical) {
		t.Fatalf("expected critical severity, got %s", report.MaxSeverity)
	}
	if !containsSignature(report, "exploit.tomcat_put_jsp") {
		t.Fatalf("expected exploit signature in report signatures %v", report.Signatures)
	}
	if len(report.Route) < 2 {
		t.Fatalf("expected multi-hop route, got %d hops", len(report.Route))
	}

	markdown := report.Markdown()
	if !strings.Contains(markdown, "Attack route") || !strings.Contains(markdown, attacker) {
		t.Fatalf("markdown report missing expected content")
	}
}

func waitForReport(t *testing.T, dashboardURL, attacker string) audit.Report {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sessionID := findSession(t, dashboardURL, attacker)
		if sessionID != "" {
			return fetchReport(t, dashboardURL, sessionID, attacker)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no session recorded for attacker %s", attacker)
	return audit.Report{}
}

func findSession(t *testing.T, dashboardURL, attacker string) string {
	t.Helper()
	response := getJSON(t, dashboardURL+"/api/sessions?token=test-token")
	defer response.Body.Close()
	var records []struct {
		ID       string `json:"id"`
		SourceIP string `json:"source_ip"`
	}
	if decodeError := json.NewDecoder(response.Body).Decode(&records); decodeError != nil {
		t.Fatalf("decode sessions: %v", decodeError)
	}
	for _, record := range records {
		if record.SourceIP == attacker {
			return record.ID
		}
	}
	return ""
}

func fetchReport(t *testing.T, dashboardURL, sessionID, attacker string) audit.Report {
	t.Helper()
	response := getJSON(t, dashboardURL+"/api/report?token=test-token&session="+sessionID+"&source="+attacker)
	defer response.Body.Close()
	var report audit.Report
	if decodeError := json.NewDecoder(response.Body).Decode(&report); decodeError != nil {
		t.Fatalf("decode report: %v", decodeError)
	}
	return report
}

func getJSON(t *testing.T, url string) *http.Response {
	t.Helper()
	response, requestError := http.Get(url)
	if requestError != nil {
		t.Fatalf("GET %s: %v", url, requestError)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status %d", url, response.StatusCode)
	}
	return response
}

func containsSignature(report audit.Report, signature string) bool {
	for _, item := range report.Signatures {
		if item == signature {
			return true
		}
	}
	for _, item := range report.Timeline {
		if item.Signature == signature {
			return true
		}
	}
	return false
}
