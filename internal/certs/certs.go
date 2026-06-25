package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func EnsureSelfSigned(directory, commonName string, hosts []string) (tls.Certificate, error) {
	certificatePath := filepath.Join(directory, commonName+".crt")
	keyPath := filepath.Join(directory, commonName+".key")
	if fileExists(certificatePath) && fileExists(keyPath) {
		return tls.LoadX509KeyPair(certificatePath, keyPath)
	}
	if makeError := os.MkdirAll(directory, 0o700); makeError != nil {
		return tls.Certificate{}, makeError
	}
	privateKey, keyError := rsa.GenerateKey(rand.Reader, 2048)
	if keyError != nil {
		return tls.Certificate{}, keyError
	}
	serialNumber, serialError := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if serialError != nil {
		return tls.Certificate{}, serialError
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Core Payment Solution"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, host := range hosts {
		if parsedIP := net.ParseIP(host); parsedIP != nil {
			template.IPAddresses = append(template.IPAddresses, parsedIP)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	derBytes, createError := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if createError != nil {
		return tls.Certificate{}, createError
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if writeError := os.WriteFile(certificatePath, certificatePEM, 0o600); writeError != nil {
		return tls.Certificate{}, writeError
	}
	if writeError := os.WriteFile(keyPath, keyPEM, 0o600); writeError != nil {
		return tls.Certificate{}, writeError
	}
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func fileExists(path string) bool {
	info, statError := os.Stat(path)
	return statError == nil && !info.IsDir()
}
