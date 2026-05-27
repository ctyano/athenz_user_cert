package signer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var DEFAULT_SIGNER_TLS_CA_PATH = ""

func newSignerHTTPClient(timeoutValue, signerTLSCAPath string) (*http.Client, error) {
	timeout, _ := strconv.Atoi(strings.TrimSpace(timeoutValue))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	signerTLSCAPath = strings.TrimSpace(signerTLSCAPath)
	if signerTLSCAPath == "" {
		return client, nil
	}
	if strings.Contains(signerTLSCAPath, "://") {
		return nil, fmt.Errorf("signer TLS CA must be a local PEM file path: %s", signerTLSCAPath)
	}

	caPEM, err := os.ReadFile(signerTLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read signer TLS CA certificate from %s: %w", signerTLSCAPath, err)
	}
	if len(strings.TrimSpace(string(caPEM))) == 0 {
		return client, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("Failed to parse signer TLS CA certificate bundle")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	client.Transport = transport
	return client, nil
}

func DefaultSignerTLSCAPath() string {
	defaultPath := strings.TrimSpace(DEFAULT_SIGNER_TLS_CA_PATH)
	if defaultPath == "" || strings.Contains(defaultPath, "://") || filepath.IsAbs(defaultPath) {
		return defaultPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultPath
	}
	return filepath.Join(home, defaultPath)
}
