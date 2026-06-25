package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/sandbox"
	"github.com/ankraio/core-payment-solution/internal/session"
)

const tomcatVersion = "Apache Tomcat/9.0.30"

type webshells struct {
	mutex sync.Mutex
	paths map[string]bool
}

func main() {
	emulator := emu.New("tomcat", "legacy-tomcat-01", 8080)
	defer emulator.Close()

	shells := &webshells{paths: map[string]bool{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		handle(emulator, shells, responseWriter, request)
	})

	server := &http.Server{
		Addr:              emulator.ListenAddress(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	emulator.Logger.Info("tomcat emulator listening", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServe(); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func handle(emulator *emu.Emulator, shells *webshells, responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Server", "Apache-Coyote/1.1")
	sourceIP := emu.ClientIP(request)

	bodyBytes, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	body := string(bodyBytes)

	emulator.Emit(event.Event{
		Kind:       event.KindHTTPRequest,
		Severity:   event.SeverityInfo,
		SourceIP:   sourceIP,
		SourcePort: portOf(request.RemoteAddr),
		Summary:    fmt.Sprintf("%s %s", request.Method, request.URL.Path),
		Payload:    truncate(body, 512),
		Attributes: map[string]any{"user_agent": request.UserAgent(), "path": request.URL.Path},
	})

	if signature, found := emu.ScanHTTP(request.Method, request.URL.RequestURI(), request.Header, body); found {
		emulator.Emit(event.Event{
			Kind:       event.KindExploitAttempt,
			Severity:   signature.Severity,
			SourceIP:   sourceIP,
			SourcePort: portOf(request.RemoteAddr),
			Summary:    signature.Title + " against tomcat",
			Signature:  signature.Signature,
			Payload:    truncate(request.URL.RequestURI()+" "+body, 512),
		})
	}

	if (request.Method == http.MethodPut || request.Method == http.MethodPost) && isUploadPath(request.URL.Path) {
		handleUpload(emulator, shells, responseWriter, request, sourceIP, body)
		return
	}

	if shells.has(request.URL.Path) {
		handleWebshell(emulator, responseWriter, request, sourceIP)
		return
	}

	switch {
	case strings.HasPrefix(request.URL.Path, "/manager"):
		handleManager(emulator, responseWriter, request, sourceIP)
	case request.URL.Path == "/":
		_, _ = io.WriteString(responseWriter, rootPage)
	default:
		responseWriter.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(responseWriter, notFoundPage(request.URL.Path))
	}
}

func handleManager(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string) {
	username, password, hasAuth := request.BasicAuth()
	if !hasAuth {
		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		responseWriter.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(responseWriter, "401 Unauthorized")
		return
	}
	accepted := isManagerCredential(username, password)
	severity := event.SeverityMedium
	if accepted {
		severity = event.SeverityHigh
	}
	emulator.Emit(event.Event{
		Kind:       event.KindAuthAttempt,
		Severity:   severity,
		SourceIP:   sourceIP,
		SourcePort: portOf(request.RemoteAddr),
		Summary:    fmt.Sprintf("tomcat manager login %s as %q", outcome(accepted), username),
		Signature:  signatureFor(accepted),
		Payload:    fmt.Sprintf("user=%s password=%s", username, password),
		Attributes: map[string]any{"username": username, "password": password, "accepted": accepted},
	})
	if !accepted {
		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		responseWriter.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(responseWriter, "401 Unauthorized")
		return
	}
	_, _ = io.WriteString(responseWriter, managerPage)
}

func handleUpload(emulator *emu.Emulator, shells *webshells, responseWriter http.ResponseWriter, request *http.Request, sourceIP, body string) {
	shells.add(request.URL.Path)
	emulator.Emit(event.Event{
		Kind:       event.KindExploitAttempt,
		Severity:   event.SeverityCritical,
		SourceIP:   sourceIP,
		SourcePort: portOf(request.RemoteAddr),
		Summary:    "JSP/WAR upload (CVE-2017-12617 style) to " + request.URL.Path,
		Signature:  "exploit.tomcat_put_jsp",
		Payload:    truncate(body, 1024),
	})
	responseWriter.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(responseWriter, "")
}

func handleWebshell(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string) {
	command := request.URL.Query().Get("cmd")
	if command == "" {
		command = request.URL.Query().Get("c")
	}
	if command == "" {
		_, _ = io.WriteString(responseWriter, "")
		return
	}
	shell := sandbox.NewShell(sandbox.ShellOptions{
		Seed: 1337,
		User: "tomcat",
		Host: emulator.Machine,
		Observer: func(observation sandbox.CommandObservation) {
			emulator.Emit(event.Event{
				Kind:      event.KindCommand,
				Severity:  event.SeverityCritical,
				SourceIP:  sourceIP,
				Summary:   "webshell command: " + observation.Raw,
				Signature: firstNonEmpty(observation.Signature, "exploit.tomcat_webshell_exec"),
				Payload:   observation.Raw,
			})
		},
	})
	result := shell.Execute(command)
	_, _ = io.WriteString(responseWriter, result.Output)
}

func isUploadPath(path string) bool {
	lowered := strings.ToLower(path)
	return strings.HasSuffix(lowered, ".jsp") || strings.HasSuffix(lowered, ".jsp/") || strings.HasSuffix(lowered, ".war")
}

func isManagerCredential(username, password string) bool {
	pairs := map[string]string{"tomcat": "tomcat", "admin": "admin", "manager": "manager", "role1": "role1"}
	expected, exists := pairs[username]
	return exists && expected == password
}

func outcome(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}

func signatureFor(accepted bool) string {
	if accepted {
		return "initial_access.tomcat_default_credentials"
	}
	return "credential_access.tomcat_manager_bruteforce"
}

func (shells *webshells) add(path string) {
	shells.mutex.Lock()
	defer shells.mutex.Unlock()
	shells.paths[strings.TrimSuffix(path, "/")] = true
}

func (shells *webshells) has(path string) bool {
	shells.mutex.Lock()
	defer shells.mutex.Unlock()
	return shells.paths[strings.TrimSuffix(path, "/")]
}

func portOf(remoteAddress string) int {
	return remotePortHTTP(remoteAddress)
}

func remotePortHTTP(remoteAddress string) int {
	host := session.RemoteIP(remoteAddress)
	if host == remoteAddress {
		return 0
	}
	index := strings.LastIndex(remoteAddress, ":")
	if index < 0 {
		return 0
	}
	port := 0
	_, _ = fmt.Sscanf(remoteAddress[index+1:], "%d", &port)
	return port
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...(truncated)"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const rootPage = `<!DOCTYPE html><html><head><title>Apache Tomcat/9.0.30</title></head>
<body><h1>Apache Tomcat/9.0.30</h1><p>If you're seeing this, you've successfully installed Tomcat. Congratulations!</p>
<p><a href="/manager/html">Manager App</a></p></body></html>`

const managerPage = `<!DOCTYPE html><html><head><title>/manager</title></head><body>
<h1>Tomcat Web Application Manager</h1>
<table border="1"><tr><th>Path</th><th>Version</th><th>Running</th><th>Sessions</th></tr>
<tr><td>/</td><td>None</td><td>true</td><td>0</td></tr>
<tr><td>/payments</td><td>None</td><td>true</td><td>14</td></tr>
<tr><td>/ledger-admin</td><td>None</td><td>true</td><td>2</td></tr>
</table>
<h2>Deploy</h2><form>WAR file to deploy: <input type="file" name="deployWar"></form>
</body></html>`

func notFoundPage(path string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><h1>HTTP Status 404 - Not Found</h1><hr><p><b>Type</b> Status Report</p>
<p><b>Message</b> %s</p><hr><h3>%s</h3></body></html>`, path, tomcatVersion)
}
