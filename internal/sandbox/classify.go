package sandbox

import "strings"

type signaturePattern struct {
	needle    string
	signature string
}

var suspiciousPatterns = []signaturePattern{
	{"wget http", "tool.download.wget"},
	{"curl http", "tool.download.curl"},
	{"chmod +x", "payload.make_executable"},
	{"/dev/tcp/", "reverse_shell.bash_devtcp"},
	{"nc -e", "reverse_shell.netcat"},
	{"ncat", "reverse_shell.ncat"},
	{"bash -i", "reverse_shell.interactive_bash"},
	{"python -c", "reverse_shell.python"},
	{"base64 -d", "payload.base64_decode"},
	{"cat /etc/shadow", "credential_access.shadow"},
	{"cat /etc/passwd", "credential_access.passwd"},
	{".ssh/id_rsa", "credential_access.ssh_key"},
	{"kubectl get secrets", "credential_access.k8s_secrets"},
	{".env", "credential_access.env_file"},
	{"cardholder", "data_exfiltration.cardholder"},
	{"ledger_accounts", "data_exfiltration.ledger"},
	{"history -c", "anti_forensics.clear_history"},
	{"rm -rf", "destruction.recursive_delete"},
	{"crontab", "persistence.crontab"},
	{"systemctl", "persistence.service"},
	{"nmap", "recon.nmap"},
	{"masscan", "recon.masscan"},
}

func classify(line string) (bool, string) {
	lowered := strings.ToLower(line)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowered, pattern.needle) {
			return true, pattern.signature
		}
	}
	return false, ""
}
