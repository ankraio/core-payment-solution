//go:build linux

package main

import (
	"os"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/log"
	"github.com/ankraio/core-payment-solution/internal/transport"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	logger := log.New("sensor")
	interfaceName := envOrDefault("SENSOR_INTERFACE", "eth0")
	collectorURL := envOrDefault("COLLECTOR_URL", "http://127.0.0.1:9400")

	client := transport.NewClient(transport.ClientOptions{
		CollectorURL: collectorURL,
		Machine:      "network-sensor",
		Service:      "sensor",
	})
	defer client.Close()

	handle, openError := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if openError != nil {
		logger.Error("pcap open failed", "interface", interfaceName, "error", openError)
		os.Exit(1)
	}
	defer handle.Close()
	if filterError := handle.SetBPFFilter("tcp or icmp"); filterError != nil {
		logger.Error("bpf filter failed", "error", filterError)
	}
	logger.Info("sensor capturing", "interface", interfaceName)

	detector := newDetector()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, finding := range detector.inspect(packet, time.Now()) {
			client.Emit(event.Event{
				Kind:       event.KindScan,
				Severity:   finding.severity,
				SourceIP:   finding.sourceIP,
				DestPort:   finding.destPort,
				Summary:    finding.summary,
				Signature:  finding.signature,
				Attributes: finding.attributes,
			})
		}
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
