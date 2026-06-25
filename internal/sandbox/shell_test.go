package sandbox

import (
	"strings"
	"testing"
)

func TestShellReadsPlantedSecrets(t *testing.T) {
	var observed []CommandObservation
	shell := NewShell(ShellOptions{Seed: 1, Observer: func(observation CommandObservation) {
		observed = append(observed, observation)
	}})

	if result := shell.Execute("cat /opt/payments/.env"); !strings.Contains(result.Output, "STRIPE_API_KEY") {
		t.Fatalf("expected env file contents, got %q", result.Output)
	}
	if len(observed) != 1 || !observed[0].Suspicious {
		t.Fatalf("expected suspicious observation for .env access, got %+v", observed)
	}
	if observed[0].Signature != "credential_access.env_file" {
		t.Fatalf("unexpected signature %q", observed[0].Signature)
	}
}

func TestShellNavigationAndExit(t *testing.T) {
	shell := NewShell(ShellOptions{Seed: 1})
	if result := shell.Execute("pwd"); strings.TrimSpace(result.Output) != "/root" {
		t.Fatalf("expected /root, got %q", result.Output)
	}
	shell.Execute("cd /opt/payments/exports")
	listing := shell.Execute("ls")
	if !strings.Contains(listing.Output, "cardholder_data.csv") {
		t.Fatalf("expected cardholder export in listing, got %q", listing.Output)
	}
	if result := shell.Execute("exit"); !result.Exit {
		t.Fatalf("expected exit")
	}
}

func TestKubectlSecretsFunnel(t *testing.T) {
	shell := NewShell(ShellOptions{Seed: 1})
	result := shell.Execute("kubectl get secrets -n payments")
	if !strings.Contains(result.Output, "stripe-api-key") {
		t.Fatalf("expected fake k8s secrets, got %q", result.Output)
	}
}
