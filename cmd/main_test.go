package main

import (
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
)

func TestDefaultString(t *testing.T) {
	if got := defaultString("configured", "fallback"); got != "configured" {
		t.Fatalf("expected configured value, got %q", got)
	}
	if got := defaultString("   ", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback value, got %q", got)
	}
}

func TestResolveSignerEndpointCA(t *testing.T) {
	tests := []struct {
		name         string
		signer       string
		wantEndpoint string
		wantCA       string
	}{
		{name: "crypki", signer: "crypki", wantEndpoint: "http://localhost:10000/v3/sig/x509-cert/keys/x509-key", wantCA: "http://localhost:10000/v3/sig/x509-cert/keys/x509-key"},
		{name: "cfssl", signer: "cfssl", wantEndpoint: "http://localhost:10000/api/v1/cfssl/sign", wantCA: "http://localhost:10000/api/v1/cfssl/info"},
		{name: "zts", signer: "zts", wantEndpoint: "https://127.0.0.1:4443/zts/v1/usercert", wantCA: "/.athenz/ca.cert.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signerName := tt.signer
			endpoint := ""
			caURL := ""
			resolveSignerEndpointCA(&signerName, &endpoint, &caURL)
			if endpoint != tt.wantEndpoint {
				t.Fatalf("expected endpoint %q, got %q", tt.wantEndpoint, endpoint)
			}
			if !strings.HasSuffix(caURL, tt.wantCA) {
				t.Fatalf("expected CA URL suffix %q, got %q", tt.wantCA, caURL)
			}
		})
	}
}

func TestExecuteVersionCommand(t *testing.T) {
	output := captureStdout(t, func() {
		ExecuteVersionCommand(nil, flag.NewFlagSet("version", flag.ContinueOnError))
	})

	if !strings.Contains(output, "CLI version: "+VERSION) {
		t.Fatalf("expected version output, got %q", output)
	}
	if !strings.Contains(output, "CLI Open ID Connect Issuer:") {
		t.Fatalf("expected OIDC output, got %q", output)
	}
	if !strings.Contains(output, "CLI X.509 configuration for ZTS:") {
		t.Fatalf("expected signer output, got %q", output)
	}
}

func TestExecuteTestCommand(t *testing.T) {
	restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, ""), nil
	})
	defer restore()

	cfg := &appconfig.Settings{}
	for _, signerName := range []string{"crypki", "cfssl", "zts"} {
		t.Run(signerName, func(t *testing.T) {
			output := captureStdout(t, func() {
				ExecuteTestCommand(
					[]string{"-signer", signerName, "-ca", "stub://example.test/ca", "-debug"},
					flag.NewFlagSet("test", flag.ContinueOnError),
					cfg,
				)
			})

			if !strings.Contains(output, "Signer CA URL is set as:stub://example.test/ca") {
				t.Fatalf("expected debug CA output, got %q", output)
			}
			if !strings.Contains(output, DEFAULT_APP_NAME+" test complete") {
				t.Fatalf("expected success output, got %q", output)
			}
		})
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}

	return string(data)
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
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: &url.URL{Scheme: "stub", Host: "example.test"}},
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
}
