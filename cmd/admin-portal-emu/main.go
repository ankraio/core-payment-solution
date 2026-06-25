package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ankraio/core-payment-solution/internal/deception"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
)

func main() {
	emulator := emu.New("admin-portal", "gateway-01", 8081)
	defer emulator.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		sourceIP := emulator.ObserveHTTP(request, "")
		_, _ = io.WriteString(responseWriter, loginPage(""))
		_ = sourceIP
	})
	mux.HandleFunc("/login", func(responseWriter http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		body := request.Form.Encode()
		sourceIP := emulator.ObserveHTTP(request, body)
		username := request.FormValue("username")
		password := request.FormValue("password")
		accepted := username == "admin" && (password == "admin" || password == "admin123" || password == "changeme")
		severity := event.SeverityMedium
		if accepted {
			severity = event.SeverityHigh
		}
		emulator.Emit(event.Event{
			Kind: event.KindAuthAttempt, Severity: severity, SourceIP: sourceIP,
			Summary:    fmt.Sprintf("admin portal login %s as %q", outcome(accepted), username),
			Signature:  loginSignature(accepted),
			Payload:    fmt.Sprintf("user=%s password=%s", username, password),
			Attributes: map[string]any{"username": username, "password": password, "accepted": accepted},
		})
		if accepted {
			http.SetCookie(responseWriter, &http.Cookie{Name: "JSESSIONID", Value: "ADMIN-" + emu.Truncate(password, 6), Path: "/"})
			http.Redirect(responseWriter, request, "/dashboard", http.StatusFound)
			return
		}
		responseWriter.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(responseWriter, loginPage("Invalid credentials"))
	})
	mux.HandleFunc("/dashboard", func(responseWriter http.ResponseWriter, request *http.Request) {
		sourceIP := emulator.ObserveHTTP(request, "")
		emulator.Emit(event.Event{
			Kind: event.KindSecretAccess, Severity: event.SeverityHigh, SourceIP: sourceIP,
			Summary: "internal admin dashboard / network map viewed", Signature: "recon.internal_network_map",
		})
		_, _ = io.WriteString(responseWriter, dashboardPage())
	})

	server := &http.Server{Addr: emulator.ListenAddress(), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	emulator.Logger.Info("admin-portal emulator listening", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServe(); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func loginSignature(accepted bool) string {
	if accepted {
		return "initial_access.admin_default_credentials"
	}
	return "credential_access.admin_bruteforce"
}

func outcome(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}

func loginPage(message string) string {
	banner := ""
	if message != "" {
		banner = `<p style="color:#c00">` + message + `</p>`
	}
	return `<!DOCTYPE html><html><head><title>Core Payments - Internal Admin</title>
<style>body{font-family:Arial;background:#eef;display:flex;justify-content:center;padding-top:8%}
.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:320px}</style></head>
<body><div class="box"><h2>Core Payment Solution</h2><h4>Internal Operations Console</h4>` + banner + `
<form method="post" action="/login">
<p>Username<br><input name="username" style="width:100%"></p>
<p>Password<br><input name="password" type="password" style="width:100%"></p>
<button type="submit">Sign in</button></form>
<p style="font-size:.75rem;color:#888">v3.4.1 - authorized personnel only</p></div></body></html>`
}

func dashboardPage() string {
	return `<!DOCTYPE html><html><head><title>Operations Console</title></head><body>
<h2>Core Payment Solution - Operations</h2>
<h3>Infrastructure inventory</h3><pre>` + deception.FakeNetworkMap() + `</pre>
<h3>Quick links</h3><ul>
<li>Tomcat Manager: http://legacy-tomcat-01:8080/manager/html</li>
<li>Payments API: https://payments-api-01:8443/swagger-ui.html</li>
<li>Kubernetes API: https://k8s-control-01:6443</li>
<li>Redis cache: redis://cache-01:6379</li>
</ul></body></html>`
}
