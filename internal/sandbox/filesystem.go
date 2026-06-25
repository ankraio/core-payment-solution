package sandbox

import (
	"sort"
	"strings"

	"github.com/ankraio/core-payment-solution/internal/deception"
)

type node struct {
	name     string
	isDir    bool
	contents string
	children map[string]*node
}

type FileSystem struct {
	root *node
}

func newDir(name string) *node {
	return &node{name: name, isDir: true, children: map[string]*node{}}
}

func NewSeededFileSystem(seed int64) *FileSystem {
	root := newDir("/")
	fileSystem := &FileSystem{root: root}

	cards := deception.GenerateCards(40, seed)
	accounts := deception.GenerateAccounts(25, seed)
	transactions := deception.GenerateTransactions(accounts, 3, seed)

	var cardDump strings.Builder
	cardDump.WriteString("pan,holder_name,expiry,brand,network_token\n")
	for _, card := range cards {
		cardDump.WriteString(card.PrimaryAccount + "," + card.HolderName + "," + card.Expiry + "," + card.Brand + "," + card.Token + "\n")
	}

	var ledgerDump strings.Builder
	ledgerDump.WriteString("account_id,merchant_id,holder_name,email,balance_minor,currency,iban,status\n")
	for _, account := range accounts {
		ledgerDump.WriteString(account.AccountID + "," + account.MerchantID + "," + account.HolderName + "," +
			account.Email + "," + formatFloat(account.Balance) + "," + account.Currency + "," + account.IBAN + "," + account.Status + "\n")
	}

	var transactionDump strings.Builder
	transactionDump.WriteString("transaction_id,account_id,amount_minor,currency,status,descriptor\n")
	for _, transaction := range transactions {
		transactionDump.WriteString(transaction.TransactionID + "," + transaction.AccountID + "," +
			formatInt(transaction.AmountMinor) + "," + transaction.Currency + "," + transaction.Status + "," + transaction.Descriptor + "\n")
	}

	fileSystem.writeFile("/etc/hostname", "payments-api-01\n")
	fileSystem.writeFile("/etc/os-release", "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n")
	fileSystem.writeFile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\npayments:x:1000:1000:payments-svc:/home/payments:/bin/bash\npostgres:x:1001:1001::/var/lib/postgresql:/bin/bash\n")
	fileSystem.writeFile("/etc/shadow", "root:$6$fakehashfakehashfakehash:19000:0:99999:7:::\n")
	fileSystem.writeFile("/etc/hosts", "127.0.0.1 localhost\n10.20.0.21 payments-api-01\n")
	fileSystem.writeFile("/etc/network-inventory.txt", deception.FakeNetworkMap())

	fileSystem.writeFile("/opt/payments/.env", deception.FakeEnvFile())
	fileSystem.writeFile("/opt/payments/application.yml", "server:\n  port: 8443\nspring:\n  datasource:\n    url: jdbc:postgresql://ledger-db.internal:5432/payments\n    username: ledger_rw\n    password: S3cr3t-ledger-rw\ndebug: true\n")
	fileSystem.writeFile("/opt/payments/exports/cardholder_data.csv", cardDump.String())
	fileSystem.writeFile("/opt/payments/exports/ledger_accounts.csv", ledgerDump.String())
	fileSystem.writeFile("/opt/payments/exports/transactions.csv", transactionDump.String())

	fileSystem.writeFile("/root/.kube/config", deception.FakeKubeconfig())
	fileSystem.writeFile("/root/.bash_history", "ls -la\ncat /opt/payments/.env\nkubectl get secrets -n payments\npsql -h ledger-db.internal -U ledger_rw payments\nexit\n")
	fileSystem.writeFile("/root/.ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYdonotuseFAKEKEYdonotuseFAKEKEYdonotuse==\n-----END OPENSSH PRIVATE KEY-----\n")
	fileSystem.writeFile("/home/payments/notes.txt", "TODO: rotate vault token before audit\nledger replica creds in /opt/payments/.env\nk8s dashboard token in ~/.kube/config\n")

	return fileSystem
}

func (fileSystem *FileSystem) writeFile(path, contents string) {
	parts := splitPath(path)
	current := fileSystem.root
	for index, part := range parts {
		if index == len(parts)-1 {
			current.children[part] = &node{name: part, isDir: false, contents: contents}
			return
		}
		child, exists := current.children[part]
		if !exists || !child.isDir {
			child = newDir(part)
			current.children[part] = child
		}
		current = child
	}
}

func (fileSystem *FileSystem) lookup(path string) (*node, bool) {
	if path == "/" {
		return fileSystem.root, true
	}
	parts := splitPath(path)
	current := fileSystem.root
	for _, part := range parts {
		child, exists := current.children[part]
		if !exists {
			return nil, false
		}
		current = child
	}
	return current, true
}

func (fileSystem *FileSystem) Clone() *FileSystem {
	return &FileSystem{root: cloneNode(fileSystem.root)}
}

func cloneNode(original *node) *node {
	copied := &node{name: original.name, isDir: original.isDir, contents: original.contents}
	if original.children != nil {
		copied.children = make(map[string]*node, len(original.children))
		for key, child := range original.children {
			copied.children[key] = cloneNode(child)
		}
	}
	return copied
}

func (fileSystem *FileSystem) listDir(path string) ([]string, bool) {
	target, exists := fileSystem.lookup(path)
	if !exists || !target.isDir {
		return nil, false
	}
	names := make([]string, 0, len(target.children))
	for name, child := range target.children {
		if child.isDir {
			names = append(names, name+"/")
		} else {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, true
}

func splitPath(path string) []string {
	cleaned := strings.Trim(path, "/")
	if cleaned == "" {
		return nil
	}
	return strings.Split(cleaned, "/")
}

func formatFloat(value float64) string {
	return strings.TrimRight(strings.TrimRight(formatFixed(value), "0"), ".")
}
