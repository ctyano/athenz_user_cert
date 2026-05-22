package signer

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendZTSCSR(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected Authorization header, got %q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("expected json content type, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload struct {
			Name            string `json:"name"`
			CSR             string `json:"csr"`
			AttestationData string `json:"attestationData"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}
		if payload.Name != "athenz.user" {
			t.Fatalf("expected request name, got %q", payload.Name)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected request csr, got %q", payload.CSR)
		}
		if payload.AttestationData != "code=test-code" {
			t.Fatalf("expected request attestation data, got %q", payload.AttestationData)
		}

		return jsonResponse(http.StatusOK, `{"x509Certificate":"signed-cert"}`), nil
	})
	defer restore()

	headers := map[string][]string{
		"Authorization": {"Bearer token"},
	}

	err, cert := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", &headers)
	if err != nil {
		t.Fatalf("SendZTSCSR returned error: %v", err)
	}
	if cert != "signed-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendZTSCSRHandlesErrorResponse(t *testing.T) {
	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":"bad csr"}`), nil
	})
	defer restore()

	err, cert := SendZTSCSR("athenz.user", "https://zts.example/usercert", "csr-data", "code=test-code", "", nil)
	if err == nil {
		t.Fatal("expected SendZTSCSR to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
	if !strings.Contains(err.Error(), "Received non-OK status") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestGetZTSRootCAFetchesRemoteBundle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		return jsonResponse(http.StatusOK, `{"caCertificates":"remote-ca"}`), nil
	})
	defer restore()

	err, cert := GetZTSRootCA(false, "https://zts.example/ca", nil)
	if err != nil {
		t.Fatalf("GetZTSRootCA returned error: %v", err)
	}
	if cert != "remote-ca" {
		t.Fatalf("expected remote CA bundle, got %q", cert)
	}
}

func TestGetZTSRootCAHandlesErrorResponse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	originalDefaultCAURL := DEFAULT_SIGNER_ZTS_CA_URL
	DEFAULT_SIGNER_ZTS_CA_URL = filepath.Join(t.TempDir(), "missing-ca.pem")
	t.Cleanup(func() {
		DEFAULT_SIGNER_ZTS_CA_URL = originalDefaultCAURL
	})

	restore := stubZTSDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, `{"error":"missing bundle"}`), nil
	})
	defer restore()

	err, cert := GetZTSRootCA(false, "https://zts.example/ca", nil)
	if err == nil {
		t.Fatal("expected GetZTSRootCA to return an error")
	}
	if cert != "" {
		t.Fatalf("expected empty certificate on error, got %q", cert)
	}
	if !strings.Contains(err.Error(), "Received non-OK status") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestParseZTSRootCAResponseAdditionalVariants(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr string
	}{
		{
			name: "x509 certificate signer",
			body: `{"x509CertificateSigner":"signer-ca"}`,
			want: "signer-ca",
		},
		{
			name: "ca certificates",
			body: `{"caCertificates":"ca-certificates"}`,
			want: "ca-certificates",
		},
		{
			name: "certificate",
			body: `{"certificate":"certificate-field"}`,
			want: "certificate-field",
		},
		{
			name: "cert",
			body: `{"cert":"cert-field"}`,
			want: "cert-field",
		},
		{
			name:    "invalid json",
			body:    `not-json`,
			wantErr: "Failed to parse JSON response",
		},
		{
			name:    "missing bundle",
			body:    `{}`,
			wantErr: "No CA certificate bundle found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseZTSRootCAResponse([]byte(tt.body), "https://zts.example/ca", false)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func stubZTSDefaultTransport(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) func() {
	t.Helper()

	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(roundTrip)
	return func() {
		http.DefaultTransport = original
	}
}
