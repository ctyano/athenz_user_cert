package oidc

import (
	"net/url"
	"testing"
)

func TestBuildAttestationDataAddsCodeVerifier(t *testing.T) {
	result := authCodeResult{
		Code:            "test-code",
		AttestationData: "code=test-code&state=test-state",
	}

	values, err := url.ParseQuery(buildAttestationData(result, "test-verifier"))
	if err != nil {
		t.Fatalf("failed to parse attestation data: %v", err)
	}

	if got := values.Get("code"); got != "test-code" {
		t.Fatalf("expected code to be preserved, got %q", got)
	}
	if got := values.Get("state"); got != "test-state" {
		t.Fatalf("expected state to be preserved, got %q", got)
	}
	if got := values.Get("code_verifier"); got != "test-verifier" {
		t.Fatalf("expected code_verifier to be added, got %q", got)
	}
}

func TestBuildAttestationDataHandlesBareCodeInput(t *testing.T) {
	result := authCodeResult{
		Code:            "test-code",
		AttestationData: "test-code",
	}

	values, err := url.ParseQuery(buildAttestationData(result, "test-verifier"))
	if err != nil {
		t.Fatalf("failed to parse attestation data: %v", err)
	}

	if got := values.Get("code"); got != "test-code" {
		t.Fatalf("expected bare code input to become code query param, got %q", got)
	}
	if got := values.Get("code_verifier"); got != "test-verifier" {
		t.Fatalf("expected code_verifier to be added, got %q", got)
	}
}

func TestBuildAuthCodeURLIncludesPKCE(t *testing.T) {
	conf := buildOAuthConfig("https://issuer.example/auth", "https://issuer.example/token")
	conf.CodeChallenge = "test-challenge"

	authURL, err := buildAuthCodeURL(conf, "form_post")
	if err != nil {
		t.Fatalf("buildAuthCodeURL returned error: %v", err)
	}

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth url: %v", err)
	}
	values := parsedURL.Query()

	if got := values.Get("response_type"); got != "code" {
		t.Fatalf("expected response_type=code, got %q", got)
	}
	if got := values.Get("response_mode"); got != "form_post" {
		t.Fatalf("expected response_mode=form_post, got %q", got)
	}
	if got := values.Get("code_challenge"); got != "test-challenge" {
		t.Fatalf("expected code_challenge to be set, got %q", got)
	}
	if got := values.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("expected code_challenge_method=S256, got %q", got)
	}
}
