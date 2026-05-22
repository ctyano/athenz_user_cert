package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

func TestLoadAppliesConfigAndEnvOverrides(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	caPath := filepath.Join(home, "ca.pem")
	if err := os.WriteFile(configPath, []byte(`
signer:
  name: zts
endpoint: https://config.example/zts/v1/usercert
ca_cert_path: ~/ca.pem
oidc:
  issuer: https://issuer.config.example
  username_claim: email
zts:
  sign_url: https://zts.config.example/zts/v1/usercert
  ca_cert_path: ~/zts-ca.pem
`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv(envConfigPath, configPath)
	t.Setenv("HOME", home)
	t.Setenv("ATHENZ_API_URL", "https://env.example/zts/v1/usercert")
	t.Setenv("ATHENZ_ZTS_SIGN_URL", "https://zts.env.example/zts/v1/usercert")

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if settings.SignerName != "zts" {
		t.Fatalf("expected signer name from config, got %q", settings.SignerName)
	}
	if settings.Endpoint != "https://env.example/zts/v1/usercert" {
		t.Fatalf("expected endpoint from env, got %q", settings.Endpoint)
	}
	if settings.CAURL != caPath {
		t.Fatalf("expected expanded CA path %q, got %q", caPath, settings.CAURL)
	}
	if settings.UserClaim != "email" {
		t.Fatalf("expected user claim from config, got %q", settings.UserClaim)
	}
	if oidc.DEFAULT_OIDC_ISSUER != "https://issuer.config.example" {
		t.Fatalf("expected oidc issuer from config, got %q", oidc.DEFAULT_OIDC_ISSUER)
	}
	if signer.DEFAULT_SIGNER_ZTS_SIGN_URL != "https://zts.env.example/zts/v1/usercert" {
		t.Fatalf("expected zts sign url from env, got %q", signer.DEFAULT_SIGNER_ZTS_SIGN_URL)
	}
}

func TestLoadIgnoresMissingDefaultConfig(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	t.Setenv("HOME", t.TempDir())
	t.Setenv(envConfigPath, "")

	if _, err := Load(); err != nil {
		t.Fatalf("expected missing default config to be ignored, got %v", err)
	}
}

func TestLoadDoesNotTreatNestedSignerMapAsSignerName(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
signer:
  endpoint: https://config.example/zts/v1/usercert
`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv(envConfigPath, configPath)

	settings, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if settings.SignerName != "" {
		t.Fatalf("expected empty signer name, got %q", settings.SignerName)
	}
	if settings.Endpoint != "https://config.example/zts/v1/usercert" {
		t.Fatalf("expected signer endpoint, got %q", settings.Endpoint)
	}
}

func TestLoadErrorsWhenExplicitConfigIsMissing(t *testing.T) {
	restore := saveDefaults()
	defer restore()

	t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "missing.yaml"))

	if _, err := Load(); err == nil {
		t.Fatal("expected missing explicit config to return an error")
	}
}

func saveDefaults() func() {
	oidcClientID := oidc.DEFAULT_OIDC_CLIENT_ID
	oidcClientSecret := oidc.DEFAULT_OIDC_CLIENT_SECRET
	oidcIssuer := oidc.DEFAULT_OIDC_ISSUER
	oidcScopes := oidc.DEFAULT_OIDC_SCOPES
	oidcListenAddress := oidc.DEFAULT_OIDC_LISTEN_ADDRESS
	oidcAccessTokenPath := oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH
	oidcUsernameClaim := oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM

	crypkiSignURL := signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
	crypkiCAURL := signer.DEFAULT_SIGNER_CRYPKI_CA_URL
	crypkiValidity := signer.DEFAULT_SIGNER_CRYPKI_VALIDITY
	crypkiIdentifier := signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER
	crypkiTimeout := signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT

	cfsslSignURL := signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
	cfsslCAURL := signer.DEFAULT_SIGNER_CFSSL_CA_URL
	cfsslTimeout := signer.DEFAULT_SIGNER_CFSSL_TIMEOUT

	ztsSignURL := signer.DEFAULT_SIGNER_ZTS_SIGN_URL
	ztsCAURL := signer.DEFAULT_SIGNER_ZTS_CA_URL
	ztsTimeout := signer.DEFAULT_SIGNER_ZTS_TIMEOUT

	return func() {
		oidc.DEFAULT_OIDC_CLIENT_ID = oidcClientID
		oidc.DEFAULT_OIDC_CLIENT_SECRET = oidcClientSecret
		oidc.DEFAULT_OIDC_ISSUER = oidcIssuer
		oidc.DEFAULT_OIDC_SCOPES = oidcScopes
		oidc.DEFAULT_OIDC_LISTEN_ADDRESS = oidcListenAddress
		oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH = oidcAccessTokenPath
		oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM = oidcUsernameClaim

		signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL = crypkiSignURL
		signer.DEFAULT_SIGNER_CRYPKI_CA_URL = crypkiCAURL
		signer.DEFAULT_SIGNER_CRYPKI_VALIDITY = crypkiValidity
		signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER = crypkiIdentifier
		signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT = crypkiTimeout

		signer.DEFAULT_SIGNER_CFSSL_SIGN_URL = cfsslSignURL
		signer.DEFAULT_SIGNER_CFSSL_CA_URL = cfsslCAURL
		signer.DEFAULT_SIGNER_CFSSL_TIMEOUT = cfsslTimeout

		signer.DEFAULT_SIGNER_ZTS_SIGN_URL = ztsSignURL
		signer.DEFAULT_SIGNER_ZTS_CA_URL = ztsCAURL
		signer.DEFAULT_SIGNER_ZTS_TIMEOUT = ztsTimeout
	}
}
