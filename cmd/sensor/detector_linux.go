//go:build linux

package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	scanWindow        = 10 * time.Second
	distinctPortLimit = 10
	distinctHostLimit = 10
	pingSweepLimit    = 8
)

type finding struct {
	severity   event.Severity
	sourceIP   string
	destPort   int
	summary    string
	signature  string
	attributes map[string]any
}

type sourceState struct {
	ports       map[int]time.Time
	hosts       map[string]time.Time
	pingTargets map[string]time.Time
	fired       map[string]time.Time
}

type detector struct {
	mutex   sync.Mutex
	sources map[string]*sourceState
}

func newDetector() *detector {
	return &detector{sources: make(map[string]*sourceState)}
}

func (engine *detector) state(sourceIP string) *sourceState {
	state, exists := engine.sources[sourceIP]
	if !exists {
		state = &sourceState{
			ports:       map[int]time.Time{},
			hosts:       map[string]time.Time{},
			pingTargets: map[string]time.Time{},
			fired:       map[string]time.Time{},
		}
		engine.sources[sourceIP] = state
	}
	return state
}

func (engine *detector) inspect(packet gopacket.Packet, now time.Time) []finding {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil
	}
	sourceIP := networkLayer.NetworkFlow().Src().String()
	destinationIP := networkLayer.NetworkFlow().Dst().String()

	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	state := engine.state(sourceIP)
	var findings []finding

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		if icmp != nil && icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			state.pingTargets[destinationIP] = now
			evictMap(state.pingTargets, now)
			if len(state.pingTargets) >= pingSweepLimit && engine.shouldFire(state, "ping_sweep", now) {
				findings = append(findings, finding{
					severity: event.SeverityMedium, sourceIP: sourceIP,
					summary:   fmt.Sprintf("ICMP ping sweep across %d hosts", len(state.pingTargets)),
					signature: "recon.ping_sweep",
				})
			}
		}
		return findings
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return findings
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if tcp == nil {
		return findings
	}
	destPort := int(tcp.DstPort)

	if scanType := stealthScanType(tcp); scanType != "" && engine.shouldFire(state, scanType, now) {
		findings = append(findings, finding{
			severity: event.SeverityHigh, sourceIP: sourceIP, destPort: destPort,
			summary:   "stealth " + scanType + " detected",
			signature: "recon." + scanType,
		})
	}

	if tcp.SYN && !tcp.ACK {
		state.ports[destPort] = now
		state.hosts[destinationIP] = now
		evictPorts(state.ports, now)
		evictMap(state.hosts, now)
		if len(state.ports) >= distinctPortLimit && engine.shouldFire(state, "port_scan", now) {
			findings = append(findings, finding{
				severity: event.SeverityHigh, sourceIP: sourceIP, destPort: destPort,
				summary:    fmt.Sprintf("TCP SYN port scan: %d distinct ports in %s", len(state.ports), scanWindow),
				signature:  "recon.syn_port_scan",
				attributes: map[string]any{"distinct_ports": len(state.ports)},
			})
		}
		if len(state.hosts) >= distinctHostLimit && engine.shouldFire(state, "host_sweep", now) {
			findings = append(findings, finding{
				severity: event.SeverityHigh, sourceIP: sourceIP,
				summary:    fmt.Sprintf("TCP host sweep: %d distinct hosts in %s", len(state.hosts), scanWindow),
				signature:  "recon.host_sweep",
				attributes: map[string]any{"distinct_hosts": len(state.hosts)},
			})
		}
	}
	return findings
}

func stealthScanType(tcp *layers.TCP) string {
	switch {
	case !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG:
		return "null_scan"
	case tcp.FIN && !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.PSH && !tcp.URG:
		return "fin_scan"
	case tcp.FIN && tcp.PSH && tcp.URG && !tcp.SYN && !tcp.ACK && !tcp.RST:
		return "xmas_scan"
	default:
		return ""
	}
}

func (engine *detector) shouldFire(state *sourceState, key string, now time.Time) bool {
	if last, exists := state.fired[key]; exists && now.Sub(last) < scanWindow {
		return false
	}
	state.fired[key] = now
	return true
}

func evictPorts(ports map[int]time.Time, now time.Time) {
	for port, seenAt := range ports {
		if now.Sub(seenAt) > scanWindow {
			delete(ports, port)
		}
	}
}

func evictMap(items map[string]time.Time, now time.Time) {
	for key, seenAt := range items {
		if now.Sub(seenAt) > scanWindow {
			delete(items, key)
		}
	}
}
