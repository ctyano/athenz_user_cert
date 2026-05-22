package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateCSRAcceptsURISANWithScheme(t *testing.T) {
	cn := "user.alice"
	empty := ""
	uri := "spiffe://example.com/user/alice"

	err, _, csrPEM := GenerateCSR("", &cn, &empty, &empty, &empty, &uri)
	if err != nil {
		t.Fatalf("GenerateCSR returned error for valid URI SAN: %v", err)
	}
	if csrPEM == nil {
		t.Fatal("expected CSR PEM block for valid URI SAN")
	}
}

func TestGenerateCSRRejectsURISANWithoutScheme(t *testing.T) {
	cn := "user.alice"
	empty := ""
	uri := "example.com/user/alice"

	err, _, csrPEM := GenerateCSR("", &cn, &empty, &empty, &empty, &uri)
	if err == nil {
		t.Fatal("expected GenerateCSR to reject URI SAN without scheme")
	}
	if csrPEM != nil {
		t.Fatal("expected no CSR PEM block when URI SAN is invalid")
	}
}

func TestReadCSRRejectsInvalidInput(t *testing.T) {
	csrPath := filepath.Join(t.TempDir(), "invalid.csr")
	if err := os.WriteFile(csrPath, []byte("not-a-csr"), 0600); err != nil {
		t.Fatalf("failed to write invalid csr: %v", err)
	}

	if err, _ := ReadCSR(csrPath); err == nil {
		t.Fatal("expected invalid csr input to return an error")
	}

	if err, _ := ReadCSR(filepath.Join(t.TempDir(), "missing.csr")); err == nil {
		t.Fatal("expected missing csr file to return an error")
	}
}

func TestReadCSRParsesDERInput(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "user.alice"},
	}, privateKey)
	if err != nil {
		t.Fatalf("failed to create csr: %v", err)
	}

	csrPath := filepath.Join(t.TempDir(), "valid.csr")
	if err := os.WriteFile(csrPath, csrDER, 0600); err != nil {
		t.Fatalf("failed to write csr: %v", err)
	}

	if err, csr := ReadCSR(csrPath); err != nil || csr.Subject.CommonName != "user.alice" {
		t.Fatalf("expected DER csr to be parsed, csr=%#v err=%v", csr, err)
	}
}

func TestWritePEMRejectsMissingDirectory(t *testing.T) {
	err := WritePEM(&pem.Block{Type: "TEST", Bytes: []byte("payload")}, filepath.Join(t.TempDir(), "missing", "cert.pem"))
	if err == nil {
		t.Fatal("expected WritePEM to return an error when parent directory is missing")
	}
}

func TestGenerateX509TemplateErrorAndSubjectPaths(t *testing.T) {
	t.Run("invalid creation date", func(t *testing.T) {
		opt := &X509Options{
			CommonName: "user.alice",
			ValidFrom:  "not-a-date",
			ValidFor:   time.Hour,
			KeyUsage:   x509.KeyUsageDigitalSignature,
		}
		if err, _ := GenerateX509Template(opt, nil, nil); err == nil {
			t.Fatal("expected invalid ValidFrom to return an error")
		}
	})

	t.Run("copies CA subject and CA options", func(t *testing.T) {
		opt := &X509Options{
			CommonName: "user.alice",
			San:        "example.com,127.0.0.1",
			ValidFor:   time.Hour,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageDigitalSignature,
		}
		cacert := &x509.Certificate{
			Subject: pkix.Name{
				Country:            []string{"JP"},
				Organization:       []string{"Example Org"},
				OrganizationalUnit: []string{"Example Unit"},
				Locality:           []string{"Tokyo"},
				Province:           []string{"Tokyo"},
				StreetAddress:      []string{"1 Example"},
				PostalCode:         []string{"100-0000"},
				SerialNumber:       "1234",
			},
		}

		err, cert := GenerateX509Template(opt, nil, cacert)
		if err != nil {
			t.Fatalf("GenerateX509Template returned error: %v", err)
		}
		if cert.Subject.Organization[0] != "Example Org" {
			t.Fatalf("expected organization copied from CA subject, got %#v", cert.Subject.Organization)
		}
		if !cert.IsCA {
			t.Fatal("expected generated certificate to be a CA")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Fatalf("expected cert sign usage to be added, got %v", cert.KeyUsage)
		}
		if cert.ExtKeyUsage != nil {
			t.Fatalf("expected CA ext key usage to be nil, got %#v", cert.ExtKeyUsage)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
			t.Fatalf("expected DNS SAN to be parsed, got %#v", cert.DNSNames)
		}
		if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
			t.Fatalf("expected IP SAN to be parsed, got %#v", cert.IPAddresses)
		}
	})
}

func TestVerifyCertificateRejectsUnknownCA(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          newSerialNumber(t),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other CA key: %v", err)
	}
	otherTemplate := &x509.Certificate{
		SerialNumber:          newSerialNumber(t),
		Subject:               pkix.Name{CommonName: "Other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("failed to create other CA certificate: %v", err)
	}
	otherCert, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatalf("failed to parse other CA certificate: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: newSerialNumber(t),
		Subject:      pkix.Name{CommonName: "user.alice"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, otherCert, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	if err := VerifyCertificate(leafCert, caCert); err == nil || !strings.Contains(err.Error(), "Failed to verify certificate") {
		t.Fatalf("expected verification error, got %v", err)
	}
}

func newSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("failed to create serial number: %v", err)
	}
	return serialNumber
}
