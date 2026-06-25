package sandbox

import "strings"

func processList() string {
	return "" +
		"  PID TTY          TIME CMD\n" +
		"    1 ?        00:00:04 systemd\n" +
		"  412 ?        00:00:00 sshd\n" +
		"  778 ?        00:02:11 java -jar payments-api.jar -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8000\n" +
		"  901 ?        00:00:33 postgres\n" +
		" 1203 ?        00:00:09 redis-server\n" +
		" 1456 pts/0    00:00:00 bash\n" +
		" 1490 pts/0    00:00:00 ps\n"
}

func netstatOutput() string {
	return "" +
		"Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 10.20.0.21:5432         10.20.0.40:5432         ESTABLISHED\n" +
		"tcp        0      0 10.20.0.21:6379         10.20.0.50:6379         ESTABLISHED\n"
}

func ifconfigOutput() string {
	return "" +
		"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
		"        inet 10.20.0.21  netmask 255.255.255.0  broadcast 10.20.0.255\n" +
		"        ether 02:42:0a:14:00:15  txqueuelen 0  (Ethernet)\n" +
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0\n"
}

func kubectlOutput(arguments []string) string {
	joined := strings.Join(arguments, " ")
	switch {
	case strings.Contains(joined, "get secrets"):
		return "" +
			"NAME                     TYPE                                  DATA   AGE\n" +
			"payments-db-credentials  Opaque                                3      214d\n" +
			"stripe-api-key           Opaque                                1      214d\n" +
			"vault-token              Opaque                                1      88d\n" +
			"default-token-7q2xn      kubernetes.io/service-account-token   3      214d\n"
	case strings.Contains(joined, "get pods"):
		return "" +
			"NAME                            READY   STATUS    RESTARTS   AGE\n" +
			"payments-api-7d9f8c6b5-2xk4p    1/1     Running   0          12d\n" +
			"payments-api-7d9f8c6b5-9wlmz    1/1     Running   0          12d\n" +
			"ledger-worker-5c8d9-abcde       1/1     Running   2          5d\n" +
			"redis-0                         1/1     Running   0          30d\n"
	case strings.Contains(joined, "get nodes"):
		return "" +
			"NAME             STATUS   ROLES           AGE    VERSION\n" +
			"k8s-control-01   Ready    control-plane   214d   v1.27.3\n" +
			"k8s-worker-01    Ready    <none>          214d   v1.27.3\n" +
			"k8s-worker-02    Ready    <none>          214d   v1.27.3\n"
	case strings.Contains(joined, "version"):
		return "Client Version: v1.27.3\nServer Version: v1.27.3\n"
	default:
		return "error: the server doesn't have a resource type \"" + strings.Join(arguments, " ") + "\"\n"
	}
}
