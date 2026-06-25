package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/certs"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
)

func main() {
	emulator := emu.New("kube-apiserver", "k8s-control-01", 6443)
	defer emulator.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		sourceIP := emulator.ObserveHTTP(request, "")
		serve(emulator, responseWriter, request, sourceIP)
	})

	certificate, certError := certs.EnsureSelfSigned(emu.CertDirectory(), "kube-apiserver",
		[]string{"localhost", "127.0.0.1", "k8s-control-01", "kubernetes", "kubernetes.default"})
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
	emulator.Logger.Info("kube-apiserver emulator listening (https)", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServeTLS("", ""); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func serve(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP string) {
	path := request.URL.Path
	anonymous := request.Header.Get("Authorization") == ""

	switch {
	case path == "/version":
		writeJSON(responseWriter, http.StatusOK, map[string]any{
			"major": "1", "minor": "27", "gitVersion": "v1.27.3", "platform": "linux/amd64",
		})
	case path == "/healthz" || path == "/livez" || path == "/readyz":
		_, _ = responseWriter.Write([]byte("ok"))
	case path == "/api":
		writeJSON(responseWriter, http.StatusOK, map[string]any{
			"kind": "APIVersions", "versions": []string{"v1"},
			"serverAddressByClientCIDRs": []map[string]string{{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.20.0.60:6443"}},
		})
	case path == "/apis":
		writeJSON(responseWriter, http.StatusOK, apiGroupList())
	case path == "/api/v1":
		writeJSON(responseWriter, http.StatusOK, coreResourceList())
	case strings.Contains(path, "/secrets"):
		emulator.Emit(event.Event{
			Kind: event.KindSecretAccess, Severity: event.SeverityCritical, SourceIP: sourceIP,
			Summary: "kubernetes secrets enumerated via API", Signature: secretSignature(anonymous),
			Attributes: map[string]any{"anonymous": anonymous, "path": path},
		})
		writeJSON(responseWriter, http.StatusOK, secretList())
	case strings.Contains(path, "/pods"):
		maybeAnonymous(emulator, sourceIP, anonymous, path)
		writeJSON(responseWriter, http.StatusOK, podList())
	case strings.Contains(path, "/nodes"):
		maybeAnonymous(emulator, sourceIP, anonymous, path)
		writeJSON(responseWriter, http.StatusOK, nodeList())
	case strings.HasSuffix(path, "/namespaces"):
		writeJSON(responseWriter, http.StatusOK, namespaceList())
	case strings.Contains(path, "/serviceaccounts"):
		maybeAnonymous(emulator, sourceIP, anonymous, path)
		writeJSON(responseWriter, http.StatusOK, map[string]any{"kind": "ServiceAccountList", "apiVersion": "v1", "items": []any{}})
	default:
		writeJSON(responseWriter, http.StatusForbidden, forbiddenStatus(path))
	}
}

func maybeAnonymous(emulator *emu.Emulator, sourceIP string, anonymous bool, path string) {
	if !anonymous {
		return
	}
	emulator.Emit(event.Event{
		Kind: event.KindExploitAttempt, Severity: event.SeverityHigh, SourceIP: sourceIP,
		Summary: "anonymous access to kubernetes API: " + path, Signature: "k8s.anonymous_access",
		Attributes: map[string]any{"path": path},
	})
}

func secretSignature(anonymous bool) string {
	if anonymous {
		return "k8s.anonymous_secret_access"
	}
	return "credential_access.k8s_secrets"
}

func apiGroupList() map[string]any {
	groups := []string{"apps", "batch", "rbac.authorization.k8s.io", "networking.k8s.io"}
	items := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		items = append(items, map[string]any{
			"name":     group,
			"versions": []map[string]string{{"groupVersion": group + "/v1", "version": "v1"}},
			"preferredVersion": map[string]string{"groupVersion": group + "/v1", "version": "v1"},
		})
	}
	return map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": items}
}

func coreResourceList() map[string]any {
	resources := []map[string]any{
		{"name": "pods", "namespaced": true, "kind": "Pod", "verbs": []string{"get", "list"}},
		{"name": "secrets", "namespaced": true, "kind": "Secret", "verbs": []string{"get", "list"}},
		{"name": "services", "namespaced": true, "kind": "Service", "verbs": []string{"get", "list"}},
		{"name": "nodes", "namespaced": false, "kind": "Node", "verbs": []string{"get", "list"}},
		{"name": "namespaces", "namespaced": false, "kind": "Namespace", "verbs": []string{"get", "list"}},
	}
	return map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": resources}
}

func secretList() map[string]any {
	items := []map[string]any{
		secretItem("payments-db-credentials", map[string]string{
			"username": "ledger_rw", "password": "S3cr3t-ledger-rw", "host": "ledger-db.internal",
		}),
		secretItem("stripe-api-key", map[string]string{"api_key": "fake_stripe_honeypot_key_not_real"}),
		secretItem("vault-token", map[string]string{"token": "hvs.CAESIJfakeFAKEtokenDOnotUSE"}),
	}
	return map[string]any{"kind": "SecretList", "apiVersion": "v1", "items": items}
}

func secretItem(name string, data map[string]string) map[string]any {
	encoded := make(map[string]string, len(data))
	for key, value := range data {
		encoded[key] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "payments"},
		"type":     "Opaque",
		"data":     encoded,
	}
}

func podList() map[string]any {
	names := []string{"payments-api-7d9f8c6b5-2xk4p", "payments-api-7d9f8c6b5-9wlmz", "ledger-worker-5c8d9-abcde", "redis-0"}
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": name, "namespace": "payments"},
			"status":   map[string]any{"phase": "Running", "podIP": "10.244.1." + string(rune('0'+len(name)%9))},
		})
	}
	return map[string]any{"kind": "PodList", "apiVersion": "v1", "items": items}
}

func nodeList() map[string]any {
	names := []string{"k8s-control-01", "k8s-worker-01", "k8s-worker-02"}
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": name},
			"status":   map[string]any{"nodeInfo": map[string]string{"kubeletVersion": "v1.27.3"}},
		})
	}
	return map[string]any{"kind": "NodeList", "apiVersion": "v1", "items": items}
}

func namespaceList() map[string]any {
	names := []string{"default", "kube-system", "payments", "ledger", "monitoring"}
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{"metadata": map[string]any{"name": name}})
	}
	return map[string]any{"kind": "NamespaceList", "apiVersion": "v1", "items": items}
}

func forbiddenStatus(path string) map[string]any {
	return map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"message": "forbidden: User \"system:anonymous\" cannot get path \"" + path + "\"",
		"reason":  "Forbidden", "code": 403,
	}
}

func writeJSON(responseWriter http.ResponseWriter, status int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	_ = json.NewEncoder(responseWriter).Encode(payload)
}
