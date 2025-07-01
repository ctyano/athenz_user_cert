package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"net"
	"net/url"
	"strings"
)

// GenerateKey generates a private key for the specified algorithm.
// Supported algorithms are "RSA", "ECDSA", and "Ed25519".
func GenerateCSR(algorithm string, cn, dnsarg, emailarg, iparg, uriarg *string) (error, *pem.Block) {
	privateKey, err := GenerateKey(algorithm)
	if err != nil {
		log.Fatalf("Failed to generate a key: %s", err)
	}

	var sandns, sanemail []string
	var sanip []net.IP
	var sanuri []*url.URL

	if *dnsarg != "" {
		sandns = strings.Split(*dnsarg, ",")
	}
	if *emailarg != "" {
		sanemail = strings.Split(*emailarg, ",")
	}
	if *iparg != "" {
		ips := strings.Split(*iparg, ",")
		for _, v := range ips {
			ip := net.ParseIP(strings.TrimSpace(v))
			if ip != nil {
				sanip = append(sanip, ip)
			}
		}
	}
	if *uriarg != "" {
		uris := strings.Split(*uriarg, ",")
		for _, v := range uris {
			uri, err := url.Parse(v)
			if err == nil && uri.Scheme != "" {
				log.Fatalf("Invalid uri [%s]: %s", v, err)
				return err, nil
			}
			sanuri = append(sanuri, uri)
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: *cn,
		},
		DNSNames:       sandns,
		EmailAddresses: sanemail,
		IPAddresses:    sanip,
		URIs:           sanuri,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		log.Fatalf("Failed to create csr: %w", err)
		return err, nil
	}

	return nil, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
}
