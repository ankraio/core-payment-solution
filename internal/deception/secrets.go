package deception

import (
	"encoding/base64"
	"fmt"
)

type Credential struct {
	System   string `json:"system"`
	Username string `json:"username"`
	Password string `json:"password"`
	Note     string `json:"note"`
}

func FakeCredentials() []Credential {
	return []Credential{
		{System: "tomcat-manager", Username: "tomcat", Password: "tomcat", Note: "legacy app server, decommission Q3"},
		{System: "postgres-ledger", Username: "ledger_ro", Password: "Pa55w0rd-ledger!", Note: "read replica for reporting"},
		{System: "redis-cache", Username: "default", Password: "", Note: "no auth - internal only"},
		{System: "vault-root", Username: "root", Password: "hvs.CAESIJfakeFAKEtokenDOnotUSE", Note: "break-glass token"},
		{System: "k8s-admin", Username: "admin", Password: "kubeadmin-2023", Note: "cluster bootstrap"},
	}
}

func FakeEnvFile() string {
	return "" +
		"DATABASE_URL=postgres://ledger_rw:S3cr3t-ledger-rw@ledger-db.internal:5432/payments\n" +
		"REDIS_URL=redis://cache.internal:6379/0\n" +
		"STRIPE_API_KEY=fake_stripe_honeypot_key_not_real\n" +
		"JWT_SIGNING_KEY=" + base64.StdEncoding.EncodeToString([]byte("fake-signing-key-do-not-use")) + "\n" +
		"VAULT_ADDR=https://vault.internal:8200\n" +
		"VAULT_TOKEN=hvs.CAESIJfakeFAKEtokenDOnotUSE\n" +
		"KUBECONFIG=/root/.kube/config\n"
}

func FakeKubeconfig() string {
	return "" +
		"apiVersion: v1\n" +
		"kind: Config\n" +
		"clusters:\n" +
		"- cluster:\n" +
		"    server: https://k8s-control.internal:6443\n" +
		"    insecure-skip-tls-verify: true\n" +
		"  name: payments-prod\n" +
		"contexts:\n" +
		"- context:\n" +
		"    cluster: payments-prod\n" +
		"    namespace: payments\n" +
		"    user: cluster-admin\n" +
		"  name: payments-prod\n" +
		"current-context: payments-prod\n" +
		"users:\n" +
		"- name: cluster-admin\n" +
		"  user:\n" +
		"    token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImZ" + "ZmFrZSJ9.fake.payload\n"
}

func FakeNetworkMap() string {
	return "" +
		"# Internal infrastructure inventory (CONFIDENTIAL)\n" +
		"10.20.0.10   gateway-01        api-gateway, nginx\n" +
		"10.20.0.21   payments-api-01   spring-boot 2.7, jdwp:8000 (DEBUG LEFT ON)\n" +
		"10.20.0.22   payments-api-02   spring-boot 2.7\n" +
		"10.20.0.31   legacy-tomcat-01  tomcat 9.0.30, manager exposed\n" +
		"10.20.0.40   ledger-db-01      postgres 14 (primary)\n" +
		"10.20.0.41   ledger-db-02      postgres 14 (replica)\n" +
		"10.20.0.50   cache-01          redis 6 (no auth)\n" +
		"10.20.0.60   k8s-control-01    kube-apiserver:6443, kubelet:10250\n" +
		"10.20.0.61   k8s-worker-01     kubelet:10250\n" +
		"10.20.0.62   k8s-worker-02     kubelet:10250\n" +
		"10.20.0.99   vault-01          vault:8200\n"
}

func FakeSecretValue(name string) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("fake-secret-%s-do-not-use", name)))
}
