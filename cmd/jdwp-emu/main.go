package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/sandbox"
	"github.com/ankraio/core-payment-solution/internal/session"
)

const handshake = "JDWP-Handshake"

func main() {
	emulator := emu.New("jdwp", "payments-api-01", 8000)
	defer emulator.Close()

	listener, listenError := net.Listen("tcp", emulator.ListenAddress())
	if listenError != nil {
		emulator.Logger.Error("listen failed", "error", listenError)
		return
	}
	emulator.Logger.Info("jdwp emulator listening", "address", emulator.ListenAddress())
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
	_ = connection.SetDeadline(time.Now().Add(5 * time.Minute))

	received := make([]byte, len(handshake))
	if _, readError := io.ReadFull(connection, received); readError != nil {
		return
	}
	if string(received) != handshake {
		return
	}
	if _, writeError := connection.Write([]byte(handshake)); writeError != nil {
		return
	}
	emulator.Emit(event.Event{
		Kind: event.KindExploitAttempt, Severity: event.SeverityHigh, SourceIP: sourceIP,
		Summary:   "JDWP debugger handshake completed (remote debug port exposed)",
		Signature: "exploit.jdwp_handshake",
	})

	shell := sandbox.NewShell(sandbox.ShellOptions{
		Seed: 1337, User: "payments", Host: emulator.Machine,
		Observer: func(observation sandbox.CommandObservation) {
			emulator.Emit(event.Event{
				Kind: event.KindCommand, Severity: event.SeverityCritical, SourceIP: sourceIP,
				Summary:   "jdwp exec command: " + observation.Raw,
				Signature: firstNonEmpty(observation.Signature, "exploit.jdwp_remote_code_execution"),
				Payload:   observation.Raw,
			})
		},
	})

	for {
		packet, readError := readPacket(connection)
		if readError != nil {
			return
		}
		reply := dispatch(emulator, sourceIP, shell, packet)
		if _, writeError := connection.Write(reply); writeError != nil {
			return
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Minute))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type packet struct {
	id         uint32
	commandSet byte
	command    byte
	data       []byte
}

func readPacket(connection net.Conn) (packet, error) {
	header := make([]byte, 11)
	if _, readError := io.ReadFull(connection, header); readError != nil {
		return packet{}, readError
	}
	length := binary.BigEndian.Uint32(header[0:4])
	identifier := binary.BigEndian.Uint32(header[4:8])
	commandSet := header[9]
	command := header[10]
	bodyLength := int(length) - 11
	body := make([]byte, 0)
	if bodyLength > 0 && bodyLength < 1<<20 {
		body = make([]byte, bodyLength)
		if _, readError := io.ReadFull(connection, body); readError != nil {
			return packet{}, readError
		}
	}
	return packet{id: identifier, commandSet: commandSet, command: command, data: body}, nil
}

func dispatch(emulator *emu.Emulator, sourceIP string, shell *sandbox.Shell, incoming packet) []byte {
	commandName := commandLabel(incoming.commandSet, incoming.command)
	severity := event.SeverityHigh
	signature := "exploit.jdwp_command"
	if isExecuteAttempt(incoming.commandSet, incoming.command) {
		severity = event.SeverityCritical
		signature = "exploit.jdwp_remote_code_execution_attempt"
	}
	emulator.Emit(event.Event{
		Kind: event.KindExploitAttempt, Severity: severity, SourceIP: sourceIP,
		Summary:   "JDWP command: " + commandName,
		Signature: signature,
		Payload:   emu.Truncate(fmt.Sprintf("set=%d cmd=%d data=%x", incoming.commandSet, incoming.command, incoming.data), 512),
	})

	switch {
	case incoming.commandSet == 1 && incoming.command == 1:
		return replyPacket(incoming.id, versionData())
	case incoming.commandSet == 1 && incoming.command == 7:
		return replyPacket(incoming.id, idSizesData())
	case incoming.commandSet == 1 && incoming.command == 2:
		return replyPacket(incoming.id, classesBySignatureData())
	case incoming.commandSet == 1 && incoming.command == 3:
		return replyPacket(incoming.id, allClassesEmpty())
	case incoming.commandSet == 1 && incoming.command == 16:
		command := parseJDWPString(incoming.data)
		if command != "" {
			shell.Execute(command)
		}
		return replyPacket(incoming.id, fakeObjectID())
	case incoming.commandSet == 9 && incoming.command == 6:
		return replyPacket(incoming.id, invokeReplyData())
	default:
		return replyPacket(incoming.id, nil)
	}
}

func parseJDWPString(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	length := binary.BigEndian.Uint32(data[:4])
	if int(length) > len(data)-4 {
		return ""
	}
	return string(data[4 : 4+length])
}

func idSizesData() []byte {
	buffer := new(bytes.Buffer)
	for index := 0; index < 5; index++ {
		_ = binary.Write(buffer, binary.BigEndian, uint32(8))
	}
	return buffer.Bytes()
}

func classesBySignatureData() []byte {
	buffer := new(bytes.Buffer)
	_ = binary.Write(buffer, binary.BigEndian, uint32(1))
	buffer.WriteByte(1)
	_ = binary.Write(buffer, binary.BigEndian, uint64(0x00000000000000a1))
	_ = binary.Write(buffer, binary.BigEndian, uint32(7))
	return buffer.Bytes()
}

func fakeObjectID() []byte {
	buffer := new(bytes.Buffer)
	_ = binary.Write(buffer, binary.BigEndian, uint64(0x00000000000000b2))
	return buffer.Bytes()
}

func invokeReplyData() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte('L')
	_ = binary.Write(buffer, binary.BigEndian, uint64(0))
	buffer.WriteByte('L')
	_ = binary.Write(buffer, binary.BigEndian, uint64(0))
	return buffer.Bytes()
}

func isExecuteAttempt(commandSet, command byte) bool {
	if commandSet == 9 && command == 6 {
		return true
	}
	if commandSet == 3 && command == 3 {
		return true
	}
	if commandSet == 15 {
		return true
	}
	return false
}

func commandLabel(commandSet, command byte) string {
	switch {
	case commandSet == 1 && command == 1:
		return "VirtualMachine.Version"
	case commandSet == 1 && command == 2:
		return "VirtualMachine.ClassesBySignature"
	case commandSet == 1 && command == 3:
		return "VirtualMachine.AllClasses"
	case commandSet == 1 && command == 16:
		return "VirtualMachine.CreateString"
	case commandSet == 3 && command == 3:
		return "ReferenceType.Methods"
	case commandSet == 9 && command == 6:
		return "ObjectReference.InvokeMethod"
	case commandSet == 15:
		return "EventRequest.Set"
	default:
		return fmt.Sprintf("Unknown(set=%d,cmd=%d)", commandSet, command)
	}
}

func replyPacket(identifier uint32, data []byte) []byte {
	buffer := new(bytes.Buffer)
	length := uint32(11 + len(data))
	_ = binary.Write(buffer, binary.BigEndian, length)
	_ = binary.Write(buffer, binary.BigEndian, identifier)
	buffer.WriteByte(0x80)
	_ = binary.Write(buffer, binary.BigEndian, uint16(0))
	buffer.Write(data)
	return buffer.Bytes()
}

func versionData() []byte {
	buffer := new(bytes.Buffer)
	writeJDWPString(buffer, "Java Debug Wire Protocol (Reference Implementation) version 11.0")
	_ = binary.Write(buffer, binary.BigEndian, uint32(11))
	_ = binary.Write(buffer, binary.BigEndian, uint32(0))
	writeJDWPString(buffer, "11.0.20")
	writeJDWPString(buffer, "OpenJDK 64-Bit Server VM")
	return buffer.Bytes()
}

func allClassesEmpty() []byte {
	buffer := new(bytes.Buffer)
	_ = binary.Write(buffer, binary.BigEndian, uint32(0))
	return buffer.Bytes()
}

func writeJDWPString(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	buffer.WriteString(value)
}
