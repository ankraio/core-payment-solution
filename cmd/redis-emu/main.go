package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/session"
)

var fakeKeys = map[string]string{
	"session:admin":            "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJ1c2VyIn0",
	"config:stripe_api_key":    "fake_stripe_honeypot_key_not_real",
	"config:db_password":       "S3cr3t-ledger-rw",
	"cache:cardholder:412...":  "{\"pan\":\"4111111111111111\",\"cvv\":\"123\"}",
	"queue:payouts:pending":    "847 items",
	"feature:maintenance_mode": "false",
}

func main() {
	emulator := emu.New("redis", "cache-01", 6379)
	defer emulator.Close()

	listener, listenError := net.Listen("tcp", emulator.ListenAddress())
	if listenError != nil {
		emulator.Logger.Error("listen failed", "error", listenError)
		return
	}
	emulator.Logger.Info("redis emulator listening", "address", emulator.ListenAddress())
	for {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			continue
		}
		go handle(emulator, connection)
	}
}

func handle(emulator *emu.Emulator, connection net.Conn) {
	defer connection.Close()
	sourceIP := session.RemoteIP(connection.RemoteAddr().String())
	emulator.Connection(sourceIP, emu.RemotePort(connection.RemoteAddr().String()))
	_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))

	reader := bufio.NewReader(connection)
	for {
		arguments, readError := readCommand(reader)
		if readError != nil {
			return
		}
		if len(arguments) == 0 {
			continue
		}
		command := strings.ToUpper(arguments[0])
		response, suspicious, signature := dispatch(command, arguments)
		if suspicious {
			emulator.Emit(event.Event{
				Kind: event.KindSecretAccess, Severity: event.SeverityHigh, SourceIP: sourceIP,
				Summary: "redis command: " + strings.Join(arguments, " "), Signature: signature,
				Payload: strings.Join(arguments, " "),
			})
		} else {
			emulator.Emit(event.Event{
				Kind: event.KindCommand, Severity: event.SeverityLow, SourceIP: sourceIP,
				Summary: "redis command: " + command, Payload: strings.Join(arguments, " "),
			})
		}
		if _, writeError := connection.Write([]byte(response)); writeError != nil {
			return
		}
		_ = connection.SetDeadline(time.Now().Add(10 * time.Minute))
	}
}

func dispatch(command string, arguments []string) (string, bool, string) {
	switch command {
	case "PING":
		return "+PONG\r\n", false, ""
	case "AUTH":
		return "+OK\r\n", true, "credential_access.redis_auth"
	case "INFO":
		return bulkString(redisInfo()), false, ""
	case "CONFIG":
		if len(arguments) >= 2 && strings.EqualFold(arguments[1], "get") {
			return configGet(arguments), true, "recon.redis_config"
		}
		return "+OK\r\n", false, ""
	case "KEYS":
		return keysReply(), true, "data_exfiltration.redis_keys"
	case "GET":
		if len(arguments) >= 2 {
			if value, exists := fakeKeys[arguments[1]]; exists {
				return bulkString(value), true, "data_exfiltration.redis_value"
			}
		}
		return "$-1\r\n", false, ""
	case "SCAN":
		return keysReply(), true, "data_exfiltration.redis_keys"
	case "COMMAND":
		return "*0\r\n", false, ""
	case "SELECT", "CLIENT", "HELLO":
		return "+OK\r\n", false, ""
	case "QUIT":
		return "+OK\r\n", false, ""
	default:
		return "-ERR unknown command '" + command + "'\r\n", false, ""
	}
}

func keysReply() string {
	var builder strings.Builder
	builder.WriteString("*" + strconv.Itoa(len(fakeKeys)) + "\r\n")
	for key := range fakeKeys {
		builder.WriteString(bulkString(key))
	}
	return builder.String()
}

func configGet(arguments []string) string {
	pattern := "*"
	if len(arguments) >= 3 {
		pattern = arguments[2]
	}
	values := map[string]string{"requirepass": "", "dir": "/data", "maxmemory": "2147483648", "bind": "0.0.0.0"}
	pairs := make([]string, 0)
	for key, value := range values {
		if pattern == "*" || strings.Contains(key, strings.Trim(pattern, "*")) {
			pairs = append(pairs, key, value)
		}
	}
	var builder strings.Builder
	builder.WriteString("*" + strconv.Itoa(len(pairs)) + "\r\n")
	for _, item := range pairs {
		builder.WriteString(bulkString(item))
	}
	return builder.String()
}

func redisInfo() string {
	return "# Server\r\nredis_version:6.2.6\r\nos:Linux 5.15.0-91-generic x86_64\r\nprocess_id:1203\r\n" +
		"# Clients\r\nconnected_clients:3\r\n# Keyspace\r\ndb0:keys=" + strconv.Itoa(len(fakeKeys)) + ",expires=0\r\n"
}

func bulkString(value string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
}

func readCommand(reader *bufio.Reader) ([]string, error) {
	firstLine, readError := reader.ReadString('\n')
	if readError != nil {
		return nil, readError
	}
	firstLine = strings.TrimRight(firstLine, "\r\n")
	if firstLine == "" {
		return nil, nil
	}
	if !strings.HasPrefix(firstLine, "*") {
		return strings.Fields(firstLine), nil
	}
	count, parseError := strconv.Atoi(firstLine[1:])
	if parseError != nil {
		return nil, parseError
	}
	arguments := make([]string, 0, count)
	for index := 0; index < count; index++ {
		lengthLine, lineError := reader.ReadString('\n')
		if lineError != nil {
			return nil, lineError
		}
		lengthLine = strings.TrimRight(lengthLine, "\r\n")
		if !strings.HasPrefix(lengthLine, "$") {
			continue
		}
		length, lengthError := strconv.Atoi(lengthLine[1:])
		if lengthError != nil {
			return nil, lengthError
		}
		buffer := make([]byte, length+2)
		if _, readFullError := readFull(reader, buffer); readFullError != nil {
			return nil, readFullError
		}
		arguments = append(arguments, string(buffer[:length]))
	}
	return arguments, nil
}

func readFull(reader *bufio.Reader, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		read, readError := reader.Read(buffer[total:])
		if read > 0 {
			total += read
		}
		if readError != nil {
			return total, readError
		}
	}
	return total, nil
}
