package emu

import (
	"crypto/tls"
	"os"
)

func CertDirectory() string {
	if directory := os.Getenv("CERT_DIRECTORY"); directory != "" {
		return directory
	}
	return "/var/lib/honeypot/certs"
}

func TLSConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
}
