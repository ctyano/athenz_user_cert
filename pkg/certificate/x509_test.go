package certificate

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
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
}

func TestWritePEMRejectsMissingDirectory(t *testing.T) {
	err := WritePEM(&pem.Block{Type: "TEST", Bytes: []byte("payload")}, filepath.Join(t.TempDir(), "missing", "cert.pem"))
	if err == nil {
		t.Fatal("expected WritePEM to return an error when parent directory is missing")
	}
}
