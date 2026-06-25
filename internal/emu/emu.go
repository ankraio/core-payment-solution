package emu

import (
	"os"
	"strconv"

	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/log"
	"github.com/ankraio/core-payment-solution/internal/transport"
)

type Emulator struct {
	Machine    string
	Service    string
	ListenPort int
	Client     *transport.Client
	Logger     *log.Logger
}

func New(service, defaultMachine string, listenPort int) *Emulator {
	machine := os.Getenv("MACHINE")
	if machine == "" {
		machine = defaultMachine
	}
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://collector:9400"
	}
	client := transport.NewClient(transport.ClientOptions{
		CollectorURL: collectorURL,
		Machine:      machine,
		Service:      service,
	})
	return &Emulator{
		Machine:    machine,
		Service:    service,
		ListenPort: listenPort,
		Client:     client,
		Logger:     log.New("emu." + service),
	}
}

func (emulator *Emulator) ListenAddress() string {
	if address := os.Getenv("LISTEN_ADDRESS"); address != "" {
		return address
	}
	return ":" + strconv.Itoa(emulator.ListenPort)
}

func (emulator *Emulator) Emit(item event.Event) {
	if item.DestPort == 0 {
		item.DestPort = emulator.ListenPort
	}
	emulator.Client.Emit(item)
}

func (emulator *Emulator) Connection(sourceIP string, sourcePort int) {
	emulator.Emit(event.Event{
		Kind:       event.KindConnection,
		Severity:   event.SeverityInfo,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		Summary:    "connection opened to " + emulator.Service,
	})
}

func (emulator *Emulator) Close() {
	emulator.Client.Close()
}
