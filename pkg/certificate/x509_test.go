package certificate

import "testing"

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
