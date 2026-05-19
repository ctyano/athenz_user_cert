package signer

import (
	"encoding/json"
	"testing"
)

func TestGetZTSRootCAParsesCertificateAuthorityBundleCerts(t *testing.T) {
	want := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	body, err := json.Marshal(map[string]string{
		"name":  "athenz",
		"certs": want,
	})
	if err != nil {
		t.Fatalf("failed to marshal response body: %v", err)
	}

	got, err := parseZTSRootCAResponse(body, "https://zts.example/ca", false)
	if err != nil {
		t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected CA bundle from certs field, got %q", got)
	}
}

func TestGetZTSRootCAParsesCACertBundle(t *testing.T) {
	want := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"
	body, err := json.Marshal(map[string]string{
		"caCertBundle": want,
	})
	if err != nil {
		t.Fatalf("failed to marshal response body: %v", err)
	}

	got, err := parseZTSRootCAResponse(body, "https://zts.example/ca", false)
	if err != nil {
		t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected CA bundle from caCertBundle field, got %q", got)
	}
}

func TestNewZTSHTTPClientAllowsMissingDefaultLocalCAFile(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = t.TempDir() + "/missing-ca.pem"
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	client, err := newZTSHTTPClient(DEFAULT_SIGNER_ZTS_CA_URL)
	if err != nil {
		t.Fatalf("newZTSHTTPClient returned error for missing default CA file: %v", err)
	}
	if client == nil {
		t.Fatal("expected http client when default CA file is missing")
	}
}

func TestGetZTSRootCAReturnsEmptyWhenDefaultLocalCAFileMissing(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = t.TempDir() + "/missing-ca.pem"
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	err, got := GetZTSRootCA(false, DEFAULT_SIGNER_ZTS_CA_URL, nil)
	if err != nil {
		t.Fatalf("GetZTSRootCA returned error for missing default CA file: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty CA bundle when default CA file is missing, got %q", got)
	}
}

func TestNewZTSHTTPClientAllowsMissingDefaultLocalCAFileForRemoteSource(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = t.TempDir() + "/missing-ca.pem"
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	client, err := newZTSHTTPClient("https://zts.example/ca")
	if err != nil {
		t.Fatalf("newZTSHTTPClient returned error for remote source with missing default CA file: %v", err)
	}
	if client == nil {
		t.Fatal("expected http client for remote source when default CA file is missing")
	}
}
