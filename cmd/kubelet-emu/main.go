package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/certs"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/sandbox"
)

func main() {
	emulator := emu.New("kubelet", "k8s-worker-01", 10250)
	defer emulator.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		body := readBody(request)
		sourceIP := emulator.ObserveHTTP(request, body)
		serve(emulator, responseWriter, request, sourceIP, body)
	})

	certificate, certError := certs.EnsureSelfSigned(emu.CertDirectory(), "kubelet",
		[]string{"localhost", "127.0.0.1", "k8s-worker-01"})
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
	emulator.Logger.Info("kubelet emulator listening (https)", "address", emulator.ListenAddress())
	if serveError := server.ListenAndServeTLS("", ""); serveError != nil {
		emulator.Logger.Error("serve failed", "error", serveError)
	}
}

func serve(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP, body string) {
	path := request.URL.Path
	switch {
	case path == "/healthz":
		_, _ = responseWriter.Write([]byte("ok"))
	case path == "/metrics" || path == "/metrics/cadvisor":
		_, _ = io.WriteString(responseWriter, "# HELP kubelet_running_pods Number of pods\nkubelet_running_pods 4\n")
	case path == "/pods" || path == "/runningpods/":
		writeJSON(responseWriter, podList())
	case strings.HasPrefix(path, "/run/"):
		handleRun(emulator, responseWriter, request, sourceIP, body)
	case strings.HasPrefix(path, "/exec/"):
		emulator.Emit(event.Event{
			Kind: event.KindExploitAttempt, Severity: event.SeverityCritical, SourceIP: sourceIP,
			Summary: "kubelet streaming exec attempt: " + path, Signature: "exploit.kubelet_exec",
		})
		responseWriter.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(responseWriter, "/cri/exec/redirect")
	default:
		responseWriter.WriteHeader(http.StatusNotFound)
	}
}

func handleRun(emulator *emu.Emulator, responseWriter http.ResponseWriter, request *http.Request, sourceIP, body string) {
	command := request.URL.Query().Get("cmd")
	if command == "" {
		for _, value := range request.URL.Query()["cmd"] {
			command = command + " " + value
		}
	}
	command = strings.TrimSpace(command)
	if command == "" && body != "" {
		command = strings.TrimSpace(strings.TrimPrefix(body, "cmd="))
	}
	shell := sandbox.NewShell(sandbox.ShellOptions{
		Seed: 1337, User: "root", Host: emulator.Machine,
		Observer: func(observation sandbox.CommandObservation) {
			emulator.Emit(event.Event{
				Kind: event.KindCommand, Severity: event.SeverityCritical, SourceIP: sourceIP,
				Summary:   "kubelet exec command: " + observation.Raw,
				Signature: firstNonEmpty(observation.Signature, "exploit.kubelet_exec"),
				Payload:   observation.Raw,
			})
		},
	})
	emulator.Emit(event.Event{
		Kind: event.KindExploitAttempt, Severity: event.SeverityCritical, SourceIP: sourceIP,
		Summary: "kubelet /run exec on container", Signature: "exploit.kubelet_run_exec",
	})
	if command == "" {
		responseWriter.WriteHeader(http.StatusBadRequest)
		return
	}
	result := shell.Execute(command)
	_, _ = io.WriteString(responseWriter, result.Output)
}

func podList() map[string]any {
	return map[string]any{
		"kind": "PodList", "apiVersion": "v1",
		"items": []map[string]any{
			{"metadata": map[string]any{"name": "payments-api-7d9f8c6b5-2xk4p", "namespace": "payments"}},
			{"metadata": map[string]any{"name": "redis-0", "namespace": "payments"}},
		},
	}
}

func readBody(request *http.Request) string {
	bodyBytes, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	return string(bodyBytes)
}

func writeJSON(responseWriter http.ResponseWriter, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(responseWriter).Encode(payload)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
