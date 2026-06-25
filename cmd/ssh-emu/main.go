package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/sandbox"
	"github.com/ankraio/core-payment-solution/internal/session"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var weakCredentials = map[string]string{
	"root":     "root",
	"root2":    "toor",
	"admin":    "admin",
	"tomcat":   "tomcat",
	"ubuntu":   "ubuntu",
	"postgres": "postgres",
	"payments": "payments123",
}

type attemptTracker struct {
	mutex    sync.Mutex
	attempts map[string]int
}

func (tracker *attemptTracker) record(sourceIP string) int {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()
	tracker.attempts[sourceIP]++
	return tracker.attempts[sourceIP]
}

func main() {
	emulator := emu.New("ssh", "payments-api-01", 2222)
	defer emulator.Close()

	tracker := &attemptTracker{attempts: map[string]int{}}

	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			sourceIP := session.RemoteIP(metadata.RemoteAddr().String())
			count := tracker.record(sourceIP)
			accepted := acceptCredential(metadata.User(), string(password), count)
			severity := event.SeverityLow
			if !accepted {
				severity = event.SeverityMedium
			}
			emulator.Emit(event.Event{
				Kind:       event.KindAuthAttempt,
				Severity:   severity,
				SourceIP:   sourceIP,
				SourcePort: remotePort(metadata.RemoteAddr()),
				Summary:    fmt.Sprintf("ssh login %s as %q", outcome(accepted), metadata.User()),
				Payload:    fmt.Sprintf("user=%s password=%s", metadata.User(), string(password)),
				Attributes: map[string]any{"username": metadata.User(), "password": string(password), "accepted": accepted, "attempt": count},
			})
			if accepted {
				emulator.Emit(event.Event{
					Kind:       event.KindAuthSuccess,
					Severity:   event.SeverityHigh,
					SourceIP:   sourceIP,
					SourcePort: remotePort(metadata.RemoteAddr()),
					Summary:    fmt.Sprintf("ssh access granted to %q", metadata.User()),
					Signature:  "initial_access.ssh_weak_credentials",
				})
				return &ssh.Permissions{Extensions: map[string]string{"user": metadata.User()}}, nil
			}
			return nil, fmt.Errorf("permission denied")
		},
	}

	hostKey, keyError := generateHostKey()
	if keyError != nil {
		emulator.Logger.Error("host key generation failed", "error", keyError)
		return
	}
	serverConfig.AddHostKey(hostKey)

	listener, listenError := net.Listen("tcp", emulator.ListenAddress())
	if listenError != nil {
		emulator.Logger.Error("listen failed", "error", listenError)
		return
	}
	emulator.Logger.Info("ssh emulator listening", "address", emulator.ListenAddress())

	for {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			emulator.Logger.Error("accept failed", "error", acceptError)
			continue
		}
		go handleConnection(emulator, serverConfig, connection)
	}
}

func handleConnection(emulator *emu.Emulator, serverConfig *ssh.ServerConfig, rawConnection net.Conn) {
	defer rawConnection.Close()
	sourceIP := session.RemoteIP(rawConnection.RemoteAddr().String())
	emulator.Connection(sourceIP, remotePort(rawConnection.RemoteAddr()))

	_ = rawConnection.SetDeadline(time.Now().Add(15 * time.Minute))
	serverConnection, channels, requests, handshakeError := ssh.NewServerConn(rawConnection, serverConfig)
	if handshakeError != nil {
		return
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)

	username := "root"
	if serverConnection.Permissions != nil {
		if value, exists := serverConnection.Permissions.Extensions["user"]; exists && value != "" {
			username = value
		}
	}

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, channelRequests, acceptError := newChannel.Accept()
		if acceptError != nil {
			continue
		}
		go handleSession(emulator, channel, channelRequests, sourceIP, username)
	}
}

func handleSession(emulator *emu.Emulator, channel ssh.Channel, requests <-chan *ssh.Request, sourceIP, username string) {
	defer channel.Close()
	interactive := make(chan bool, 1)
	go func() {
		for request := range requests {
			switch request.Type {
			case "pty-req":
				_ = request.Reply(true, nil)
			case "shell":
				_ = request.Reply(true, nil)
				interactive <- true
			case "exec":
				command := parseExecPayload(request.Payload)
				_ = request.Reply(true, nil)
				runSingleCommand(emulator, channel, sourceIP, username, command)
				interactive <- false
			default:
				_ = request.Reply(false, nil)
			}
		}
	}()

	if !<-interactive {
		return
	}
	runInteractiveShell(emulator, channel, sourceIP, username)
}

func runInteractiveShell(emulator *emu.Emulator, channel ssh.Channel, sourceIP, username string) {
	shell := newShell(emulator, sourceIP, username)
	terminal := term.NewTerminal(channel, "")
	terminal.SetPrompt(shell.Prompt())
	banner := "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n" +
		" * Documentation:  https://help.ubuntu.com\r\n\r\nLast login: " +
		time.Now().Add(-26*time.Hour).Format("Mon Jan 2 15:04:05 2006") + " from 10.20.0.5\r\n"
	_, _ = io.WriteString(terminal, banner)

	for {
		line, readError := terminal.ReadLine()
		if readError != nil {
			return
		}
		result := shell.Execute(line)
		if result.Output != "" {
			_, _ = io.WriteString(terminal, normalizeNewlines(result.Output))
		}
		if result.Exit {
			return
		}
		terminal.SetPrompt(shell.Prompt())
	}
}

func runSingleCommand(emulator *emu.Emulator, channel ssh.Channel, sourceIP, username, command string) {
	shell := newShell(emulator, sourceIP, username)
	result := shell.Execute(command)
	_, _ = io.WriteString(channel, normalizeNewlines(result.Output))
	_, _ = channel.SendRequest("exit-status", false, exitStatusPayload(0))
}

func newShell(emulator *emu.Emulator, sourceIP, username string) *sandbox.Shell {
	return sandbox.NewShell(sandbox.ShellOptions{
		Seed: 1337,
		User: username,
		Host: emulator.Machine,
		Observer: func(observation sandbox.CommandObservation) {
			severity := event.SeverityLow
			kind := event.KindCommand
			if observation.Suspicious {
				severity = event.SeverityHigh
				if isExfil(observation.Signature) {
					kind = event.KindSecretAccess
				}
			}
			emulator.Emit(event.Event{
				Kind:      kind,
				Severity:  severity,
				SourceIP:  sourceIP,
				Summary:   "shell command: " + observation.Raw,
				Signature: observation.Signature,
				Payload:   observation.Raw,
			})
		},
	})
}

func isExfil(signature string) bool {
	switch signature {
	case "credential_access.shadow", "credential_access.passwd", "credential_access.ssh_key",
		"credential_access.k8s_secrets", "credential_access.env_file",
		"data_exfiltration.cardholder", "data_exfiltration.ledger":
		return true
	default:
		return false
	}
}

func acceptCredential(username, password string, attempt int) bool {
	if expected, exists := weakCredentials[username]; exists && expected == password {
		return true
	}
	if username == "root" && (password == "root" || password == "toor" || password == "password") {
		return true
	}
	return attempt >= 3
}

func outcome(accepted bool) string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}

func generateHostKey() (ssh.Signer, error) {
	privateKey, keyError := rsa.GenerateKey(rand.Reader, 2048)
	if keyError != nil {
		return nil, keyError
	}
	return ssh.NewSignerFromKey(privateKey)
}

func remotePort(address net.Addr) int {
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		return tcpAddress.Port
	}
	return 0
}

func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return string(payload)
	}
	length := binary.BigEndian.Uint32(payload[:4])
	if int(length) <= len(payload)-4 {
		return string(payload[4 : 4+length])
	}
	return string(payload[4:])
}

func exitStatusPayload(code uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, code)
	return buffer
}

func normalizeNewlines(text string) string {
	result := make([]byte, 0, len(text)+8)
	for index := 0; index < len(text); index++ {
		if text[index] == '\n' && (index == 0 || text[index-1] != '\r') {
			result = append(result, '\r', '\n')
			continue
		}
		result = append(result, text[index])
	}
	return string(result)
}
