//go:build !linux

package main

import "github.com/ankraio/core-payment-solution/internal/log"

func main() {
	logger := log.New("sensor")
	logger.Error("the packet sensor requires Linux with libpcap (network_mode: host); build and run it on the Linux deployment target")
}
