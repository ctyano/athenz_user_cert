package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeyHelpers(t *testing.T) {
	privateKey, err := GenerateKey("RSA")
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	pemBlock, err := PrivateKeyToPEM(privateKey)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM returned error: %v", err)
	}
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY PEM block, got %q", pemBlock.Type)
	}

	publicKey, err := PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivateKey returned error: %v", err)
	}

	err, ciphertext := Encrypt(publicKey, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	err, plaintext := Decrypt(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("expected decrypted plaintext, got %q", string(plaintext))
	}
}

func TestKeyAlgorithmsAndUsage(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantUsage x509.KeyUsage
	}{
		{name: "rsa", algorithm: "RSA", wantUsage: x509.KeyUsageKeyEncipherment},
		{name: "ecdsa", algorithm: "ECDSA", wantUsage: x509.KeyUsageDigitalSignature},
		{name: "ed25519", algorithm: "Ed25519", wantUsage: x509.KeyUsageDigitalSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GenerateKey(tt.algorithm)
			if err != nil {
				t.Fatalf("GenerateKey returned error: %v", err)
			}

			publicKey, err := PublicKeyFromPrivateKey(privateKey)
			if err != nil {
				t.Fatalf("PublicKeyFromPrivateKey returned error: %v", err)
			}
			if publicKey == nil {
				t.Fatal("expected public key")
			}
			if _, err := x509.MarshalPKIXPublicKey(publicKey); err != nil {
				t.Fatalf("failed to marshal public key: %v", err)
			}

			var algorithm x509.PublicKeyAlgorithm
			switch tt.algorithm {
			case "RSA":
				algorithm = x509.RSA
			case "ECDSA":
				algorithm = x509.ECDSA
			case "Ed25519":
				algorithm = x509.Ed25519
			}

			err, usage := keyUsageFromAlgorithm(algorithm)
			if err != nil {
				t.Fatalf("keyUsageFromAlgorithm returned error: %v", err)
			}
			if usage != tt.wantUsage {
				t.Fatalf("expected key usage %v, got %v", tt.wantUsage, usage)
			}
		})
	}

	if _, err := GenerateKey("DSA"); err == nil {
		t.Fatal("expected unsupported key algorithm to return an error")
	}
	if err, _ := keyUsageFromAlgorithm(x509.UnknownPublicKeyAlgorithm); err == nil {
		t.Fatal("expected unknown public key algorithm to return an error")
	}
	if err, usage := keyUsageFromAlgorithm(x509.DSA); err != nil || usage != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected DSA to map to digital signature usage, got usage=%v err=%v", usage, err)
	}
	if err, _ := keyUsageFromAlgorithm(x509.PublicKeyAlgorithm(99)); err == nil {
		t.Fatal("expected unsupported public key algorithm to return an error")
	}
}

func TestKeyHelperErrorPaths(t *testing.T) {
	if _, err := PrivateKeyToPEM("not-a-private-key"); err == nil {
		t.Fatal("expected invalid private key to return an error")
	}
	if _, err := PublicKeyFromPrivateKey("not-a-private-key"); err == nil {
		t.Fatal("expected invalid private key type to return an error")
	}
	if err, _ := Decrypt("not-a-private-key", "%%%"); err == nil {
		t.Fatal("expected invalid ciphertext to return an error")
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	if err, _ := Encrypt(&ecdsaKey.PublicKey, []byte("secret")); err == nil {
		t.Fatal("expected unsupported public key type to return an error")
	}
	if err, _ := Decrypt(ecdsaKey, base64.StdEncoding.EncodeToString([]byte("ciphertext"))); err == nil {
		t.Fatal("expected unsupported private key type to return an error")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	if err, _ := Encrypt(&rsaKey.PublicKey, make([]byte, 4096)); err == nil {
		t.Fatal("expected oversized RSA plaintext to return an error")
	}
}

func TestX509Helpers(t *testing.T) {
	cn := "user.alice"
	dns := "example.com"
	email := "alice@example.com"
	ip := "127.0.0.1"
	uri := "spiffe://example.com/user/alice"

	err, _, csrPEM := GenerateCSR("RSA", &cn, &dns, &email, &ip, &uri)
	if err != nil {
		t.Fatalf("GenerateCSR returned error: %v", err)
	}

	csrPath := filepath.Join(t.TempDir(), "user.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(csrPEM), 0600); err != nil {
		t.Fatalf("failed to write CSR: %v", err)
	}

	err, csr := ReadCSR(csrPath)
	if err != nil {
		t.Fatalf("ReadCSR returned error: %v", err)
	}

	opt := &X509Options{ValidFor: time.Hour}
	err, csrPublicKey := ParseCSRToX509Options(csr, &opt)
	if err != nil {
		t.Fatalf("ParseCSRToX509Options returned error: %v", err)
	}
	if opt.CommonName != cn {
		t.Fatalf("expected common name %q, got %q", cn, opt.CommonName)
	}
	if !strings.Contains(opt.San, "example.com") || !strings.Contains(opt.San, "127.0.0.1") {
		t.Fatalf("expected SAN list to include CSR subjects, got %q", opt.San)
	}
	if csrPublicKey == nil {
		t.Fatal("expected CSR public key")
	}

	err, certTemplate := GenerateX509Template(opt, nil, nil)
	if err != nil {
		t.Fatalf("GenerateX509Template returned error: %v", err)
	}
	if len(certTemplate.DNSNames) == 0 || len(certTemplate.IPAddresses) == 0 {
		t.Fatalf("expected SANs to be populated in certificate template: %#v", certTemplate)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caOpt := &X509Options{
		CommonName: "Example CA",
		ValidFor:   time.Hour,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageDigitalSignature,
	}
	err, caTemplate := GenerateX509Template(caOpt, nil, nil)
	if err != nil {
		t.Fatalf("GenerateX509Template returned error for CA: %v", err)
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csrPublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	if err := VerifyCertificate(leafCert, caCert); err != nil {
		t.Fatalf("VerifyCertificate returned error: %v", err)
	}
}

func TestPathAndPEMHelpers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := UserKeyPath(); got != filepath.Join(home, ".athenz/user.key.pem") {
		t.Fatalf("expected user key path, got %q", got)
	}
	if got := UserCertPath(); got != filepath.Join(home, ".athenz/user.cert.pem") {
		t.Fatalf("expected user cert path, got %q", got)
	}
	if got := CACertPath(); got != filepath.Join(home, ".athenz/ca.cert.pem") {
		t.Fatalf("expected CA cert path, got %q", got)
	}

	pemPath := filepath.Join(t.TempDir(), "key.pem")
	if err := WritePEM(&pem.Block{Type: "TEST", Bytes: []byte("payload")}, pemPath); err != nil {
		t.Fatalf("WritePEM returned error: %v", err)
	}
	data, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("failed to read PEM file: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN TEST") {
		t.Fatalf("expected PEM output, got %q", string(data))
	}
}
