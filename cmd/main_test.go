package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
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
	t.Run("cfssl ca check", func(t *testing.T) {
		restore := stubDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusUnauthorized, ""), nil
		})
		defer restore()

		output := captureStdout(t, func() {
			ExecuteTestCommand(
				[]string{"-signer", "cfssl", "-ca", "stub://example.test/ca", "-debug"},
				flag.NewFlagSet("test", flag.ContinueOnError),
				&appconfig.Settings{},
			)
		})

		if !strings.Contains(output, "Signer CA URL is set as:stub://example.test/ca") {
			t.Fatalf("expected debug CA output, got %q", output)
		}
		if !strings.Contains(output, DEFAULT_APP_NAME+" test complete") {
			t.Fatalf("expected success output, got %q", output)
		}
	})

	t.Run("crypki issues certificate with stdin password", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)
		installSuccessfulGenerateCSR(t)

		testCommandInputReader = strings.NewReader("secret\n")
		getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
			if username != "dex-user" || password != "secret" {
				t.Fatalf("unexpected password grant credentials %q/%q", username, password)
			}
			return "jwt-token", nil
		}
		sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
			if got := (*headers)["Authorization"][0]; got != "Bearer jwt-token" {
				t.Fatalf("expected crypki authorization header, got %q", got)
			}
			if !strings.Contains(csr, "Y3NyLXBheWxvYWQ=") {
				t.Fatalf("expected PEM encoded csr, got %q", csr)
			}
			return nil, "cert"
		}
		getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			if test {
				t.Fatal("expected non-test CA retrieval after certificate issuance")
			}
			if got := (*headers)["Authorization"][0]; got != "Bearer jwt-token" {
				t.Fatalf("expected crypki authorization header, got %q", got)
			}
			return nil, "ca"
		}

		output := captureStdout(t, func() {
			ExecuteTestCommand(
				[]string{"-signer", "crypki", "-username", "dex-user", "-password-stdin", "-debug"},
				flag.NewFlagSet("test", flag.ContinueOnError),
				&appconfig.Settings{},
			)
		})
		if !strings.Contains(output, "Access Token retrieved Successfully") {
			t.Fatalf("expected access token debug output, got %q", output)
		}
		if !strings.Contains(output, DEFAULT_APP_NAME+" test complete") {
			t.Fatalf("expected success output, got %q", output)
		}
	})

	t.Run("zts issues certificate with stdin password", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)
		installSuccessfulGenerateCSR(t)

		testCommandInputReader = strings.NewReader("secret\n")
		getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
			if username != "dex-user" || password != "secret" {
				t.Fatalf("unexpected password grant credentials %q/%q", username, password)
			}
			return "jwt-token", nil
		}
		sendZTSCSR = func(name, endpoint, csr, attestationData, trustSource string, headers *map[string][]string) (error, string) {
			if name != "user.alice" {
				t.Fatalf("expected derived common name, got %q", name)
			}
			if attestationData != "jwt-token" {
				t.Fatalf("expected token attestation data, got %q", attestationData)
			}
			if !strings.Contains(csr, "Y3NyLXBheWxvYWQ=") {
				t.Fatalf("expected PEM encoded csr, got %q", csr)
			}
			return nil, "cert"
		}
		getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			if test {
				t.Fatal("expected non-test CA retrieval after certificate issuance")
			}
			return nil, "ca"
		}

		output := captureStdout(t, func() {
			ExecuteTestCommand(
				[]string{"-signer", "zts", "-username", "dex-user", "-password-stdin"},
				flag.NewFlagSet("test", flag.ContinueOnError),
				&appconfig.Settings{},
			)
		})
		if !strings.Contains(output, DEFAULT_APP_NAME+" test complete") {
			t.Fatalf("expected success output, got %q", output)
		}
	})
}

func TestExecuteTestCommandReturnsError(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}

	var output bytes.Buffer
	err := executeTestCommand([]string{"-signer", "cfssl"}, flag.NewFlagSet("test", flag.ContinueOnError), &output, &appconfig.Settings{})
	if err == nil {
		t.Fatal("expected executeTestCommand to return an error")
	}
	if !strings.Contains(err.Error(), "Failed to get ca certificate") {
		t.Fatalf("expected CA retrieval error, got %v", err)
	}
}

func TestExecuteTestCommandWrapperCallsExitOnError(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}

	exitCode := -1
	exitFunc = func(code int) {
		exitCode = code
	}

	output := captureStdout(t, func() {
		ExecuteTestCommand([]string{"-signer", "cfssl"}, flag.NewFlagSet("test", flag.ContinueOnError), &appconfig.Settings{})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "Failed to get ca certificate") {
		t.Fatalf("expected error output, got %q", output)
	}
}

func TestRunMain(t *testing.T) {
	t.Run("load config failure", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()

		loadConfig = func() (*appconfig.Settings, error) {
			return nil, io.EOF
		}

		var output bytes.Buffer
		if got := runMain(nil, &output); got != 1 {
			t.Fatalf("expected exit code 1, got %d", got)
		}
		if !strings.Contains(output.String(), "Failed to load configuration") {
			t.Fatalf("expected load error output, got %q", output.String())
		}
	})

	t.Run("execute failure", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)

		loadConfig = func() (*appconfig.Settings, error) {
			return &appconfig.Settings{}, nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			return "", io.EOF
		}

		var output bytes.Buffer
		if got := runMain([]string{"-signer", "cfssl"}, &output); got != 1 {
			t.Fatalf("expected exit code 1, got %d", got)
		}
		if !strings.Contains(output.String(), "Failed to get access token") {
			t.Fatalf("expected execute error output, got %q", output.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)

		loadConfig = func() (*appconfig.Settings, error) {
			return &appconfig.Settings{}, nil
		}
		getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
			return "cached-token", nil
		}
		sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
			return nil, "cfssl-cert"
		}
		getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			return nil, ""
		}
		generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate test private key: %v", err)
			}
			var key crypto.PrivateKey = privateKey
			return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
		}

		var output bytes.Buffer
		if got := runMain([]string{"-signer", "cfssl"}, &output); got != 0 {
			t.Fatalf("expected exit code 0, got %d", got)
		}
		if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
			t.Fatalf("expected success output, got %q", output.String())
		}
	})
}

func TestMainUsesExitFunc(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	originalArgs := os.Args
	os.Args = []string{"athenzusercert", "-signer", "cfssl"}
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	loadConfig = func() (*appconfig.Settings, error) {
		return &appconfig.Settings{}, nil
	}
	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "cached-token", nil
	}
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
		return nil, "cfssl-cert"
	}
	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
		return nil, ""
	}
	generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test private key: %v", err)
		}
		var key crypto.PrivateKey = privateKey
		return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
	}

	exitCode := -1
	exitFunc = func(code int) {
		exitCode = code
	}

	output := captureStdout(t, func() {
		main()
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Signed Athenz User certificate is successfully stored at:") {
		t.Fatalf("expected success output, got %q", output)
	}
}

func TestExecuteHelp(t *testing.T) {
	var output bytes.Buffer

	if err := execute([]string{"help"}, &output, &appconfig.Settings{}); err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !strings.Contains(output.String(), "Usage of "+DEFAULT_APP_NAME) {
		t.Fatalf("expected help output, got %q", output.String())
	}
	if !strings.Contains(output.String(), "-signer") {
		t.Fatalf("expected help flags in output, got %q", output.String())
	}
}

func TestExecuteSignerFlows(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantCommonName  string
		wantCert        string
		wantCACert      string
		wantAccessToken string
		wantCAUpdated   bool
		setup           func(*testing.T)
	}{
		{
			name:            "crypki",
			args:            []string{"-signer", "crypki", "-debug"},
			wantCommonName:  "user.alice",
			wantCert:        "crypki-cert",
			wantCACert:      "crypki-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "crypki-cert"
				}
				getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "crypki-ca"
				}
			},
		},
		{
			name:            "cfssl",
			args:            []string{"-signer", "cfssl"},
			wantCommonName:  "user.alice",
			wantCert:        "cfssl-cert",
			wantCACert:      "cfssl-ca",
			wantAccessToken: "cached-token",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-ca"
				}
			},
		},
		{
			name:            "zts with derived common name",
			args:            []string{"-signer", "zts", "-debug"},
			wantCommonName:  "user.alice",
			wantCert:        "zts-cert",
			wantCACert:      "",
			wantAccessToken: "cached-token",
			wantCAUpdated:   false,
			setup: func(t *testing.T) {
				getAuthAttestationDataAndAccessTok = func(responseMode *string, debug *bool) (string, string, error) {
					return "code=test-code", "cached-token", nil
				}
				sendZTSCSR = func(name, endpoint, csr, attestationData, trustSource string, headers *map[string][]string) (error, string) {
					if attestationData != "code=test-code" {
						t.Fatalf("expected attestation data, got %q", attestationData)
					}
					return nil, "zts-cert"
				}
				getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
			},
		},
		{
			name:            "zts with explicit common name",
			args:            []string{"-signer", "zts", "-cn", "custom.name"},
			wantCommonName:  "custom.name",
			wantCert:        "zts-cert",
			wantCACert:      "zts-ca",
			wantAccessToken: "",
			wantCAUpdated:   true,
			setup: func(t *testing.T) {
				getAuthAttestationData = func(responseMode *string, debug *bool) (string, error) {
					return "code=test-code", nil
				}
				getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
					t.Fatal("did not expect username extraction when common name is provided")
					return "", nil
				}
				sendZTSCSR = func(name, endpoint, csr, attestationData, trustSource string, headers *map[string][]string) (error, string) {
					return nil, "zts-cert"
				}
				getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "zts-ca"
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := saveCmdGlobals()
			defer restore()
			installDefaultCommandStubs(t)
			tt.setup(t)

			var writtenFiles = map[string]string{}
			writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
				writtenFiles[path] = string(data)
				return nil
			}

			var sentCommonName string
			generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
				sentCommonName = *cn
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate test private key: %v", err)
				}
				var key crypto.PrivateKey = privateKey
				return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
			}

			var output bytes.Buffer
			err := execute(tt.args, &output, &appconfig.Settings{})
			if err != nil {
				t.Fatalf("execute returned error: %v", err)
			}

			if sentCommonName != tt.wantCommonName {
				t.Fatalf("expected common name %q, got %q", tt.wantCommonName, sentCommonName)
			}
			if got := writtenFiles[userCertPath()]; got != tt.wantCert {
				t.Fatalf("expected written certificate %q, got %q", tt.wantCert, got)
			}
			if tt.wantCAUpdated {
				if got := writtenFiles[caCertPath()]; got != tt.wantCACert {
					t.Fatalf("expected written CA certificate %q, got %q", tt.wantCACert, got)
				}
			} else if _, ok := writtenFiles[caCertPath()]; ok {
				t.Fatalf("did not expect CA certificate to be written")
			}
			if !strings.Contains(output.String(), "Signed Athenz User certificate is successfully stored at:") {
				t.Fatalf("expected success output, got %q", output.String())
			}
		})
	}
}

func TestExecuteReturnsError(t *testing.T) {
	restore := saveCmdGlobals()
	defer restore()
	installDefaultCommandStubs(t)

	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "cached-token", nil
	}
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}

	var output bytes.Buffer
	err := execute([]string{"-signer", "cfssl"}, &output, &appconfig.Settings{})
	if err == nil {
		t.Fatal("expected execute to return an error")
	}
	if !strings.Contains(err.Error(), "Failed to get signed certificate") {
		t.Fatalf("expected signer error, got %v", err)
	}
}

func TestExecuteSubcommands(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		var output bytes.Buffer
		if err := execute([]string{"version"}, &output, &appconfig.Settings{}); err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
	})

	t.Run("test", func(t *testing.T) {
		restore := saveCmdGlobals()
		defer restore()
		installDefaultCommandStubs(t)
		getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
			return nil, ""
		}

		var output bytes.Buffer
		if err := execute([]string{"test", "-signer", "cfssl"}, &output, &appconfig.Settings{}); err != nil {
			t.Fatalf("execute returned error: %v", err)
		}
		if !strings.Contains(output.String(), DEFAULT_APP_NAME+" test complete") {
			t.Fatalf("expected test command output, got %q", output.String())
		}
	})
}

func TestExecuteAdditionalErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		setup   func(*testing.T)
	}{
		{
			name:    "flag parse error",
			args:    []string{"-unknown-flag"},
			wantErr: "flag provided but not defined",
			setup:   func(*testing.T) {},
		},
		{
			name:    "zts auth data missing",
			args:    []string{"-signer", "zts"},
			wantErr: "Failed to get OIDC authentication data",
			setup: func(t *testing.T) {
				getAuthAttestationDataAndAccessTok = func(responseMode *string, debug *bool) (string, string, error) {
					return "", "", nil
				}
			},
		},
		{
			name:    "zts attestation missing",
			args:    []string{"-signer", "zts", "-cn", "custom.name"},
			wantErr: "Failed to get OIDC attestation data",
			setup: func(t *testing.T) {
				getAuthAttestationData = func(responseMode *string, debug *bool) (string, error) {
					return "", nil
				}
			},
		},
		{
			name:    "username extraction error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to extract Athenz User Name",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
					return "", io.EOF
				}
			},
		},
		{
			name:    "generate csr error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to generate csr",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
					return io.EOF, nil, nil
				}
			},
		},
		{
			name:    "private key pem error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to convert X.509 certificate key to PEM string",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				privateKeyToPEM = func(priv crypto.PrivateKey) (*pem.Block, error) {
					return nil, io.EOF
				}
			},
		},
		{
			name:    "write key pem error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 certificate key",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				writePEMFile = func(block *pem.Block, path string) error {
					return io.EOF
				}
			},
		},
		{
			name:    "write cert error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 certificate to",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, ""
				}
				writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
					if path == userCertPath() {
						return io.EOF
					}
					return nil
				}
			},
		},
		{
			name:    "write ca cert error",
			args:    []string{"-signer", "cfssl"},
			wantErr: "Failed to save X.509 CA certificate to",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-cert"
				}
				getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return nil, "cfssl-ca"
				}
				writeOutputFile = func(path string, data []byte, perm os.FileMode) error {
					if path == caCertPath() {
						return io.EOF
					}
					return nil
				}
			},
		},
		{
			name:    "ca retrieval error",
			args:    []string{"-signer", "crypki"},
			wantErr: "Failed to get ca certificate",
			setup: func(t *testing.T) {
				getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
					return "cached-token", nil
				}
				sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) {
					return nil, "crypki-cert"
				}
				getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) {
					return io.EOF, ""
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := saveCmdGlobals()
			defer restore()
			installDefaultCommandStubs(t)
			installSuccessfulGenerateCSR(t)
			tt.setup(t)

			var output bytes.Buffer
			err := execute(tt.args, &output, &appconfig.Settings{})
			if err == nil {
				t.Fatal("expected execute to return an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func installSuccessfulGenerateCSR(t *testing.T) {
	t.Helper()

	generateCSR = func(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *crypto.PrivateKey, *pem.Block) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate test private key: %v", err)
		}
		var key crypto.PrivateKey = privateKey
		return nil, &key, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("csr-payload")}
	}
}

func installDefaultCommandStubs(t *testing.T) {
	t.Helper()

	getAuthAttestationData = func(responseMode *string, debug *bool) (string, error) {
		return "", io.EOF
	}
	getAuthAttestationDataAndAccessTok = func(responseMode *string, debug *bool) (string, string, error) {
		return "", "", io.EOF
	}
	getAuthAccessToken = func(responseMode *string, debug *bool) (string, error) {
		return "", io.EOF
	}
	getPasswordGrantAccessToken = func(username, password string, debug *bool) (string, error) {
		return "", io.EOF
	}
	getUserNameFromAccessToken = func(rawJWT, userNameClaim string) (string, error) {
		if rawJWT == "" {
			t.Fatal("expected access token for username extraction")
		}
		return "alice", nil
	}
	privateKeyToPEM = func(priv crypto.PrivateKey) (*pem.Block, error) {
		return &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")}, nil
	}
	writePEMFile = func(block *pem.Block, path string) error { return nil }
	userKeyPath = func() string { return "/tmp/user.key.pem" }
	userCertPath = func() string { return "/tmp/user.cert.pem" }
	caCertPath = func() string { return "/tmp/ca.cert.pem" }
	writeOutputFile = func(path string, data []byte, perm os.FileMode) error { return nil }
	sendCrypkiCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	getCrypkiRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	sendCFSSLCSR = func(endpoint, csr string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	getCFSSLRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
	sendZTSCSR = func(name, endpoint, csr, attestationData, trustSource string, headers *map[string][]string) (error, string) {
		return io.EOF, ""
	}
	getZTSRootCA = func(test bool, source string, headers *map[string][]string) (error, string) { return io.EOF, "" }
}

func saveCmdGlobals() func() {
	savedLoadConfig := loadConfig
	savedGetAuthAttestationData := getAuthAttestationData
	savedGetAuthAttestationDataAndAccessTok := getAuthAttestationDataAndAccessTok
	savedGetAuthAccessToken := getAuthAccessToken
	savedGetPasswordGrantAccessToken := getPasswordGrantAccessToken
	savedGetUserNameFromAccessToken := getUserNameFromAccessToken
	savedGenerateCSR := generateCSR
	savedPrivateKeyToPEM := privateKeyToPEM
	savedWritePEMFile := writePEMFile
	savedUserKeyPath := userKeyPath
	savedUserCertPath := userCertPath
	savedCACertPath := caCertPath
	savedWriteOutputFile := writeOutputFile
	savedSendCrypkiCSR := sendCrypkiCSR
	savedGetCrypkiRootCA := getCrypkiRootCA
	savedSendCFSSLCSR := sendCFSSLCSR
	savedGetCFSSLRootCA := getCFSSLRootCA
	savedSendZTSCSR := sendZTSCSR
	savedGetZTSRootCA := getZTSRootCA
	savedExitFunc := exitFunc
	savedTestCommandInputReader := testCommandInputReader

	return func() {
		loadConfig = savedLoadConfig
		getAuthAttestationData = savedGetAuthAttestationData
		getAuthAttestationDataAndAccessTok = savedGetAuthAttestationDataAndAccessTok
		getAuthAccessToken = savedGetAuthAccessToken
		getPasswordGrantAccessToken = savedGetPasswordGrantAccessToken
		getUserNameFromAccessToken = savedGetUserNameFromAccessToken
		generateCSR = savedGenerateCSR
		privateKeyToPEM = savedPrivateKeyToPEM
		writePEMFile = savedWritePEMFile
		userKeyPath = savedUserKeyPath
		userCertPath = savedUserCertPath
		caCertPath = savedCACertPath
		writeOutputFile = savedWriteOutputFile
		sendCrypkiCSR = savedSendCrypkiCSR
		getCrypkiRootCA = savedGetCrypkiRootCA
		sendCFSSLCSR = savedSendCFSSLCSR
		getCFSSLRootCA = savedGetCFSSLRootCA
		sendZTSCSR = savedSendZTSCSR
		getZTSRootCA = savedGetZTSRootCA
		exitFunc = savedExitFunc
		testCommandInputReader = savedTestCommandInputReader
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
