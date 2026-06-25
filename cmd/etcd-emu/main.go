package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/deception"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
)

var fakeNodes = map[string]string{
	"/registry/secrets/payments/db-credentials": "ledger_rw:S3cr3t-ledger-rw@ledger-db.internal",
	"/registry/secrets/payments/stripe-api-key": "fake_stripe_honeypot_key_not_real",
	"/registry/secrets/kube-system/vault-token": "hvs.CAESIJfakeFAKEtokenDOnotUSE",
	"/payments/config/feature_flags":            "maintenance_mode=false",
}

func main() {
	emulator := emu.New("etcd", "k8s-control-01", 2379)
	defer emulator.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		sourceIP := emulator.ObserveHTTP(request, "")
		serve(emulator, responseWriter, request, sourceIP)
	})

	server := &http.Server{Addr: emulator.ListenAddress(), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	emulator.Logger.Info("etcd emulator listening", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServe(); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func serve(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string) {
	path := request.URL.Path
	switch {
	case path == "/version":
		writeJSON(responseWriter, map[string]string{"etcdserver": "3.5.9", "etcdcluster": "3.5.0"})
	case path == "/health":
		writeJSON(responseWriter, map[string]string{"health": "true"})
	case path == "/v2/keys" || path == "/v2/keys/":
		emulator.Emit(event.Event{
			Kind: event.KindSecretAccess, Severity: event.SeverityCritical, SourceIP: sourceIP,
			Summary: "etcd keyspace enumerated (unauthenticated)", Signature: "data_exfiltration.etcd_keys",
		})
		writeJSON(responseWriter, keyspaceListing())
	case strings.HasPrefix(path, "/v2/keys/"):
		key := strings.TrimPrefix(path, "/v2/keys")
		emulator.Emit(event.Event{
			Kind: event.KindSecretAccess, Severity: event.SeverityCritical, SourceIP: sourceIP,
			Summary: "etcd key read: " + key, Signature: "data_exfiltration.etcd_value",
		})
		value, exists := fakeNodes[key]
		if !exists {
			value = deception.FakeSecretValue(key)
		}
		writeJSON(responseWriter, map[string]any{
			"action": "get",
			"node":   map[string]any{"key": key, "value": value, "modifiedIndex": 42, "createdIndex": 42},
		})
	default:
		responseWriter.WriteHeader(http.StatusNotFound)
	}
}

func keyspaceListing() map[string]any {
	nodes := make([]map[string]any, 0, len(fakeNodes))
	for key, value := range fakeNodes {
		nodes = append(nodes, map[string]any{"key": key, "value": value})
	}
	return map[string]any{"action": "get", "node": map[string]any{"dir": true, "nodes": nodes}}
}

func writeJSON(responseWriter http.ResponseWriter, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(responseWriter).Encode(payload)
}
