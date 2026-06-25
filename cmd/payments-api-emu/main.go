package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/certs"
	"github.com/ankraio/core-payment-solution/internal/deception"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
)

func main() {
	emulator := emu.New("payments-api", "payments-api-01", 8443)
	defer emulator.Close()

	accounts := deception.GenerateAccounts(80, 4242)
	transactions := deception.GenerateTransactions(accounts, 4, 4242)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		body := readBody(request)
		sourceIP := emulator.ObserveHTTP(request, body)
		route(emulator, accounts, transactions, responseWriter, request, sourceIP)
	})

	certificate, certError := certs.EnsureSelfSigned(emu.CertDirectory(), "payments-api", []string{"localhost", "127.0.0.1", "payments-api-01"})
	if certError != nil {
		emulator.Logger.Error("cert generation failed", "error", certError)
		return
	}
	server := &http.Server{
		Addr:              emulator.ListenAddress(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         emu.TLSConfig(certificate),
	}
	emulator.Logger.Info("payments-api emulator listening (https)", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServeTLS("", ""); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func route(emulator *emu.Emulator, accounts []deception.Account, transactions []deception.Transaction, responseWriter http.ResponseWriter, request *http.Request, sourceIP string) {
	responseWriter.Header().Set("Server", "nginx/1.24.0")
	responseWriter.Header().Set("X-Powered-By", "Spring Boot 2.7.3")

	path := request.URL.Path
	switch {
	case path == "/" || path == "/health" || path == "/actuator/health":
		writeJSON(responseWriter, http.StatusOK, map[string]any{"status": "UP", "service": "payments-api", "version": "2.7.3"})
	case path == "/v1/openapi.json" || path == "/swagger.json" || path == "/v3/api-docs":
		writeJSON(responseWriter, http.StatusOK, openAPISpec())
	case path == "/swagger-ui.html" || path == "/swagger-ui/":
		_, _ = io.WriteString(responseWriter, swaggerPage)
	case path == "/v1/accounts":
		requireAuthOrLeak(emulator, responseWriter, request, sourceIP, accounts)
	case strings.HasPrefix(path, "/v1/accounts/"):
		serveAccount(emulator, responseWriter, request, sourceIP, accounts, transactions, strings.TrimPrefix(path, "/v1/accounts/"))
	case path == "/v1/transactions":
		writeJSON(responseWriter, http.StatusOK, map[string]any{"data": transactions[:min(50, len(transactions))]})
	case path == "/v1/cards" || strings.Contains(path, "card"):
		emulator.Emit(event.Event{
			Kind: event.KindSecretAccess, Severity: event.SeverityHigh, SourceIP: sourceIP,
			Summary: "cardholder data endpoint accessed", Signature: "data_exfiltration.cardholder",
		})
		writeJSON(responseWriter, http.StatusOK, map[string]any{"data": deception.GenerateCards(25, 4242)})
	default:
		writeJSON(responseWriter, http.StatusNotFound, map[string]any{"error": "not_found", "path": path})
	}
}

func requireAuthOrLeak(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string, accounts []deception.Account) {
	authorization := request.Header.Get("Authorization")
	if authorization == "" {
		writeJSON(responseWriter, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
		return
	}
	emulator.Emit(event.Event{
		Kind: event.KindSecretAccess, Severity: event.SeverityHigh, SourceIP: sourceIP,
		Summary: "account ledger enumerated", Signature: "data_exfiltration.ledger",
		Payload: emu.Truncate(authorization, 64),
	})
	writeJSON(responseWriter, http.StatusOK, map[string]any{"data": accounts, "total": len(accounts)})
}

func serveAccount(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string, accounts []deception.Account, transactions []deception.Transaction, identifier string) {
	identifier = strings.TrimSuffix(identifier, "/transactions")
	emulator.Emit(event.Event{
		Kind: event.KindHTTPRequest, Severity: event.SeverityLow, SourceIP: sourceIP,
		Summary: "direct object reference to account " + identifier, Signature: "exploit.idor_probe",
	})
	for _, account := range accounts {
		if account.AccountID == identifier {
			writeJSON(responseWriter, http.StatusOK, account)
			return
		}
	}
	if len(accounts) > 0 {
		writeJSON(responseWriter, http.StatusOK, accounts[0])
		return
	}
	writeJSON(responseWriter, http.StatusNotFound, map[string]any{"error": "account_not_found"})
}

func openAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.0.1",
		"info":    map[string]any{"title": "Core Payment Solution API", "version": "2.7.3"},
		"paths": map[string]any{
			"/v1/accounts":        map[string]any{"get": map[string]any{"summary": "List merchant accounts"}},
			"/v1/accounts/{id}":   map[string]any{"get": map[string]any{"summary": "Get account by id"}},
			"/v1/transactions":    map[string]any{"get": map[string]any{"summary": "List transactions"}},
			"/v1/cards":           map[string]any{"get": map[string]any{"summary": "List stored cards"}},
		},
	}
}

func readBody(request *http.Request) string {
	bodyBytes, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	return string(bodyBytes)
}

func writeJSON(responseWriter http.ResponseWriter, status int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	_ = json.NewEncoder(responseWriter).Encode(payload)
}

const swaggerPage = `<!DOCTYPE html><html><head><title>Swagger UI - Core Payment Solution</title></head>
<body><h1>Core Payment Solution API 2.7.3</h1><p>See <a href="/v3/api-docs">/v3/api-docs</a></p></body></html>`
