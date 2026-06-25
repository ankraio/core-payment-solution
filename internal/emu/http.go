package emu

import (
	"net/http"
	"os"
	"strings"

	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/session"
)

func TrustForwardedFor() bool {
	return strings.EqualFold(os.Getenv("TRUST_FORWARDED_FOR"), "true")
}

func ClientIP(request *http.Request) string {
	return session.ClientIP(request, TrustForwardedFor())
}

type HTTPSignature struct {
	Signature string
	Severity  event.Severity
	Title     string
}

func ScanHTTP(method, target string, header http.Header, body string) (HTTPSignature, bool) {
	haystack := strings.ToLower(method + " " + target + " " + headerString(header) + " " + body)

	switch {
	case strings.Contains(haystack, "${jndi:"):
		return HTTPSignature{"exploit.log4shell", event.SeverityCritical, "Log4Shell JNDI injection"}, true
	case strings.Contains(haystack, "../") || strings.Contains(haystack, "..%2f") || strings.Contains(haystack, "%2e%2e"):
		return HTTPSignature{"exploit.path_traversal", event.SeverityHigh, "Path traversal attempt"}, true
	case strings.Contains(haystack, "union select") || strings.Contains(haystack, "' or '1'='1") || strings.Contains(haystack, "or 1=1") || strings.Contains(haystack, "sleep("):
		return HTTPSignature{"exploit.sql_injection", event.SeverityHigh, "SQL injection attempt"}, true
	case strings.Contains(haystack, "<script>") || strings.Contains(haystack, "onerror="):
		return HTTPSignature{"exploit.xss", event.SeverityMedium, "Cross-site scripting attempt"}, true
	case strings.Contains(haystack, "/etc/passwd") || strings.Contains(haystack, "/etc/shadow"):
		return HTTPSignature{"exploit.lfi", event.SeverityHigh, "Local file inclusion attempt"}, true
	case strings.Contains(haystack, "() {") || strings.Contains(haystack, "() { :;"):
		return HTTPSignature{"exploit.shellshock", event.SeverityCritical, "Shellshock attempt"}, true
	default:
		return HTTPSignature{}, false
	}
}

func (emulator *Emulator) ObserveHTTP(request *http.Request, body string) string {
	sourceIP := ClientIP(request)
	emulator.Emit(event.Event{
		Kind:       event.KindHTTPRequest,
		Severity:   event.SeverityInfo,
		SourceIP:   sourceIP,
		SourcePort: RemotePort(request.RemoteAddr),
		Summary:    request.Method + " " + request.URL.Path,
		Payload:    Truncate(body, 512),
		Attributes: map[string]any{"user_agent": request.UserAgent(), "path": request.URL.Path},
	})
	if signature, found := ScanHTTP(request.Method, request.URL.RequestURI(), request.Header, body); found {
		emulator.Emit(event.Event{
			Kind:       event.KindExploitAttempt,
			Severity:   signature.Severity,
			SourceIP:   sourceIP,
			SourcePort: RemotePort(request.RemoteAddr),
			Summary:    signature.Title,
			Signature:  signature.Signature,
			Payload:    Truncate(request.URL.RequestURI()+" "+body, 512),
		})
	}
	return sourceIP
}

func RemotePort(remoteAddress string) int {
	host := session.RemoteIP(remoteAddress)
	if host == remoteAddress {
		return 0
	}
	index := strings.LastIndex(remoteAddress, ":")
	if index < 0 {
		return 0
	}
	port := 0
	for _, character := range remoteAddress[index+1:] {
		if character < '0' || character > '9' {
			break
		}
		port = port*10 + int(character-'0')
	}
	return port
}

func Truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...(truncated)"
}

func headerString(header http.Header) string {
	var builder strings.Builder
	for name, values := range header {
		builder.WriteString(name)
		builder.WriteString(": ")
		builder.WriteString(strings.Join(values, ","))
		builder.WriteString(" ")
	}
	return builder.String()
}
