package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestGetCachedAccessTokenReturnsValidJWT(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	token := makeTestJWT(t, map[string]any{
		"exp":  time.Now().Add(10 * time.Minute).Unix(),
		"name": "alice",
	})
	writeCachedAccessToken(t, token)

	got, err := getCachedAccessToken(false)
	if err != nil {
		t.Fatalf("getCachedAccessToken returned error: %v", err)
	}
	if got != token {
		t.Fatalf("expected cached token %q, got %q", token, got)
	}
}

func TestGetCachedAccessTokenRejectsExpiredJWT(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writeCachedAccessToken(t, makeTestJWT(t, map[string]any{
		"exp": time.Now().Add(-1 * time.Minute).Unix(),
	}))

	_, err := getCachedAccessToken(false)
	if err == nil {
		t.Fatal("expected expired cached token to return an error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiration error, got %v", err)
	}
}

func TestGetCachedAccessTokenRejectsMalformedJWT(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writeCachedAccessToken(t, "not-a-jwt")

	_, err := getCachedAccessToken(false)
	if err == nil {
		t.Fatal("expected malformed cached token to return an error")
	}
	if !strings.Contains(err.Error(), "invalid jwt") {
		t.Fatalf("expected invalid jwt error, got %v", err)
	}
}

func TestGetCachedAccessTokenRejectsJWTWithoutExpiry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writeCachedAccessToken(t, makeTestJWT(t, map[string]any{
		"name": "alice",
	}))

	_, err := getCachedAccessToken(false)
	if err == nil {
		t.Fatal("expected cached token without exp to return an error")
	}
	if !strings.Contains(err.Error(), "no exp claim") {
		t.Fatalf("expected missing exp error, got %v", err)
	}
}

func TestGetAuthAccessTokenUsesValidCachedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	token := makeTestJWT(t, map[string]any{
		"exp":  time.Now().Add(10 * time.Minute).Unix(),
		"name": "alice",
	})
	writeCachedAccessToken(t, token)

	originalIssuer := DEFAULT_OIDC_ISSUER
	DEFAULT_OIDC_ISSUER = "://invalid-issuer"
	t.Cleanup(func() {
		DEFAULT_OIDC_ISSUER = originalIssuer
	})

	responseMode := "form_post"
	debug := false
	got, err := GetAuthAccessToken(&responseMode, &debug)
	if err != nil {
		t.Fatalf("GetAuthAccessToken returned error: %v", err)
	}
	if got != token {
		t.Fatalf("expected cached token %q, got %q", token, got)
	}
}

func makeTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("failed to marshal jwt header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal jwt payload: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func writeCachedAccessToken(t *testing.T, token string) {
	t.Helper()

	cachePath := getAccessTokenCachePath()
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		t.Fatalf("failed to create access token cache dir: %v", err)
	}
	if err := os.WriteFile(cachePath, []byte(token), 0600); err != nil {
		t.Fatalf("failed to write access token cache: %v", err)
	}
}
