package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ankraio/core-payment-solution/internal/deception"
	"github.com/ankraio/core-payment-solution/internal/emu"
	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/session"
)

func main() {
	emulator := emu.New("ajp", "legacy-tomcat-01", 8009)
	defer emulator.Close()

	listener, listenError := net.Listen("tcp", emulator.ListenAddress())
	if listenError != nil {
		emulator.Logger.Error("listen failed", "error", listenError)
		return
	}
	emulator.Logger.Info("ajp emulator listening", "address", emulator.ListenAddress())
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
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))

	for {
		payload, readError := readPacket(connection)
		if readError != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}
		prefix := payload[0]
		if prefix == 0x0A {
			// CPing -> CPong
			_, _ = connection.Write(buildPacket([]byte{0x09}))
			continue
		}
		if prefix != 0x02 {
			continue
		}
		raw := string(payload)
		ghostcat := strings.Contains(raw, "javax.servlet.include") || strings.Contains(raw, "WEB-INF")
		signature := "recon.ajp_request"
		severity := event.SeverityMedium
		kind := event.KindHTTPRequest
		summary := "AJP forward request"
		if ghostcat {
			signature = "exploit.ghostcat_cve_2020_1938"
			severity = event.SeverityCritical
			kind = event.KindExploitAttempt
			summary = "Ghostcat (CVE-2020-1938) file read via AJP attribute injection"
		}
		emulator.Emit(event.Event{
			Kind: kind, Severity: severity, SourceIP: sourceIP,
			Summary: summary, Signature: signature,
			Payload: emu.Truncate(printable(raw), 512),
		})
		writeResponse(connection, ghostcat)
	}
}

func writeResponse(connection net.Conn, ghostcat bool) {
	body := "<html><body>Apache Tomcat/9.0.30</body></html>"
	if ghostcat {
		body = deception.FakeEnvFile() + "\n<!-- WEB-INF/web.xml -->\n" +
			"<web-app><display-name>payments</display-name></web-app>"
	}
	_, _ = connection.Write(buildPacket(sendHeaders(len(body))))
	_, _ = connection.Write(buildPacket(sendBodyChunk(body)))
	_, _ = connection.Write(buildPacket(endResponse()))
}

func sendHeaders(contentLength int) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(0x04)
	_ = binary.Write(buffer, binary.BigEndian, uint16(200))
	writeAJPString(buffer, "OK")
	_ = binary.Write(buffer, binary.BigEndian, uint16(1))
	writeAJPString(buffer, "Content-Type")
	writeAJPString(buffer, "text/plain")
	_ = contentLength
	return buffer.Bytes()
}

func sendBodyChunk(body string) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(0x03)
	_ = binary.Write(buffer, binary.BigEndian, uint16(len(body)))
	buffer.WriteString(body)
	buffer.WriteByte(0x00)
	return buffer.Bytes()
}

func endResponse() []byte {
	return []byte{0x05, 0x01}
}

func buildPacket(payload []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte('A')
	buffer.WriteByte('B')
	_ = binary.Write(buffer, binary.BigEndian, uint16(len(payload)))
	buffer.Write(payload)
	return buffer.Bytes()
}

func writeAJPString(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint16(len(value)))
	buffer.WriteString(value)
	buffer.WriteByte(0x00)
}

func readPacket(connection net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, readError := io.ReadFull(connection, header); readError != nil {
		return nil, readError
	}
	if header[0] != 0x12 || header[1] != 0x34 {
		return nil, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint16(header[2:4])
	if length == 0 || length > 16384 {
		return nil, nil
	}
	payload := make([]byte, length)
	if _, readError := io.ReadFull(connection, payload); readError != nil {
		return nil, readError
	}
	return payload, nil
}

func printable(raw string) string {
	var builder strings.Builder
	for _, character := range raw {
		if character >= 0x20 && character < 0x7f {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('.')
		}
	}
	return builder.String()
}
