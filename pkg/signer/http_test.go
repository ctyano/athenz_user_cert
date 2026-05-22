package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSendCFSSLCSR(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"Bearer token"},
	}

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected Authorization header, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload struct {
			CSR string `json:"certificate_request"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected CSR payload, got %q", payload.CSR)
		}

		return jsonResponse(http.StatusOK, `{"result":{"certificate":"cfssl-cert"}}`), nil
	})
	defer restore()

	err, cert := SendCFSSLCSR("stub://cfssl.example/sign", "csr-data", &headers)
	if err != nil {
		t.Fatalf("SendCFSSLCSR returned error: %v", err)
	}
	if cert != "cfssl-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestGetCFSSLRootCAAllowsUnauthorizedDuringTest(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, ""), nil
	})
	defer restore()

	err, cert := GetCFSSLRootCA(true, "stub://cfssl.example/info", nil)
	if err != nil {
		t.Fatalf("GetCFSSLRootCA returned error: %v", err)
	}
	if cert != "" {
		t.Fatalf("expected empty certificate, got %q", cert)
	}
}

func TestGetCFSSLRootCAParsesCertificate(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"result":{"certificate":"cfssl-ca"}}`), nil
	})
	defer restore()

	err, cert := GetCFSSLRootCA(false, "stub://cfssl.example/info", nil)
	if err != nil {
		t.Fatalf("GetCFSSLRootCA returned error: %v", err)
	}
	if cert != "cfssl-ca" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendCFSSLCSRHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":"invalid csr"}`), nil
	})
	defer restore()

	err, cert := SendCFSSLCSR("stub://cfssl.example/sign", "csr-data", nil)
	if err == nil {
		t.Fatal("expected SendCFSSLCSR to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestGetCFSSLRootCAHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, `{"error":"unavailable"}`), nil
	})
	defer restore()

	err, cert := GetCFSSLRootCA(false, "stub://cfssl.example/info", nil)
	if err == nil {
		t.Fatal("expected GetCFSSLRootCA to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestSendCrypkiCSR(t *testing.T) {
	originalIdentifier := DEFAULT_SIGNER_CRYPKI_IDENTIFIER
	originalValidity := DEFAULT_SIGNER_CRYPKI_VALIDITY
	DEFAULT_SIGNER_CRYPKI_IDENTIFIER = "athenz-user"
	DEFAULT_SIGNER_CRYPKI_VALIDITY = "600"
	t.Cleanup(func() {
		DEFAULT_SIGNER_CRYPKI_IDENTIFIER = originalIdentifier
		DEFAULT_SIGNER_CRYPKI_VALIDITY = originalValidity
	})

	headers := map[string][]string{
		"Authorization": {"Bearer token"},
	}

	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected Authorization header, got %q", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload struct {
			CSR      string `json:"csr"`
			Validity int    `json:"validity"`
			KeyMeta  struct {
				Identifier string `json:"identifier"`
			} `json:"key_meta"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if payload.CSR != "csr-data" {
			t.Fatalf("expected CSR payload, got %q", payload.CSR)
		}
		if payload.Validity != 600 {
			t.Fatalf("expected validity 600, got %d", payload.Validity)
		}
		if payload.KeyMeta.Identifier != "athenz-user" {
			t.Fatalf("expected identifier, got %q", payload.KeyMeta.Identifier)
		}

		return jsonResponse(http.StatusOK, `{"cert":"crypki-cert"}`), nil
	})
	defer restore()

	err, cert := SendCrypkiCSR("stub://crypki.example/sign", "csr-data", &headers)
	if err != nil {
		t.Fatalf("SendCrypkiCSR returned error: %v", err)
	}
	if cert != "crypki-cert" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestGetCrypkiRootCAAllowsUnauthorizedDuringTest(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, ""), nil
	})
	defer restore()

	err, cert := GetCrypkiRootCA(true, "stub://crypki.example/ca", nil)
	if err != nil {
		t.Fatalf("GetCrypkiRootCA returned error: %v", err)
	}
	if cert != "" {
		t.Fatalf("expected empty certificate, got %q", cert)
	}
}

func TestGetCrypkiRootCAParsesCertificate(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"cert":"crypki-ca"}`), nil
	})
	defer restore()

	err, cert := GetCrypkiRootCA(false, "stub://crypki.example/ca", nil)
	if err != nil {
		t.Fatalf("GetCrypkiRootCA returned error: %v", err)
	}
	if cert != "crypki-ca" {
		t.Fatalf("expected certificate, got %q", cert)
	}
}

func TestSendCrypkiCSRHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error":"invalid csr"}`), nil
	})
	defer restore()

	err, cert := SendCrypkiCSR("stub://crypki.example/sign", "csr-data", nil)
	if err == nil {
		t.Fatal("expected SendCrypkiCSR to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestGetCrypkiRootCAHandlesErrorResponse(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, `{"error":"unavailable"}`), nil
	})
	defer restore()

	err, cert := GetCrypkiRootCA(false, "stub://crypki.example/ca", nil)
	if err == nil {
		t.Fatal("expected GetCrypkiRootCA to return an error")
	}
	if cert != "" {
		t.Fatalf("expected no certificate on error, got %q", cert)
	}
}

func TestGetZTSRootCAReturnsLocalFileContents(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	want := "-----BEGIN CERTIFICATE-----\nLOCAL\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(caPath, []byte(want), 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	err, cert := GetZTSRootCA(false, caPath, nil)
	if err != nil {
		t.Fatalf("GetZTSRootCA returned error: %v", err)
	}
	if cert != want {
		t.Fatalf("expected CA contents, got %q", cert)
	}
}

func TestGetZTSLocalPath(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "empty", source: "   ", want: ""},
		{name: "http url", source: "https://zts.example/ca", want: ""},
		{name: "file url", source: "file:///tmp/ca.pem", want: "/tmp/ca.pem"},
		{name: "plain path", source: "/tmp/ca.pem", want: "/tmp/ca.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getZTSLocalPath(tt.source); got != tt.want {
				t.Fatalf("expected local path %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGetZTSRootCAAllowsUnauthorizedDuringTest(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, ""), nil
	})
	defer restore()

	err, cert := GetZTSRootCA(true, "stub://zts.example/ca", nil)
	if err != nil {
		t.Fatalf("GetZTSRootCA returned error: %v", err)
	}
	if cert != "" {
		t.Fatalf("expected empty certificate, got %q", cert)
	}
}

func TestParseZTSRootCAResponseVariants(t *testing.T) {
	t.Run("plain pem", func(t *testing.T) {
		want := "-----BEGIN CERTIFICATE-----\nRAW\n-----END CERTIFICATE-----"
		got, err := parseZTSRootCAResponse([]byte(want), "stub://zts.example/ca", false)
		if err != nil {
			t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
		}
		if got != want {
			t.Fatalf("expected raw PEM, got %q", got)
		}
	})

	t.Run("result certificate", func(t *testing.T) {
		body := []byte(`{"result":{"certificate":"bundle"}}`)
		got, err := parseZTSRootCAResponse(body, "stub://zts.example/ca", false)
		if err != nil {
			t.Fatalf("parseZTSRootCAResponse returned error: %v", err)
		}
		if got != "bundle" {
			t.Fatalf("expected nested certificate, got %q", got)
		}
	})

	t.Run("invalid json in test mode", func(t *testing.T) {
		got, err := parseZTSRootCAResponse([]byte("not-json"), "stub://zts.example/ca", true)
		if err != nil {
			t.Fatalf("expected invalid JSON to be ignored in test mode, got %v", err)
		}
		if got != "" {
			t.Fatalf("expected empty bundle, got %q", got)
		}
	})
}

func TestNewZTSHTTPClientLoadsCustomCAFile(t *testing.T) {
	certPEM := createSelfSignedCertPEM(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(certPEM), 0600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	client, err := newZTSHTTPClient(caPath)
	if err != nil {
		t.Fatalf("newZTSHTTPClient returned error: %v", err)
	}
	if client.Transport == nil {
		t.Fatal("expected TLS transport to be configured")
	}
}

func createSelfSignedCertPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func stubDefaultTransport(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) func() {
	t.Helper()

	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.RegisterProtocol("stub", roundTripFunc(roundTrip))
	http.DefaultTransport = transport
	return func() {
		http.DefaultTransport = original
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: &url.URL{Scheme: "stub", Host: "example.test"}},
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
}
