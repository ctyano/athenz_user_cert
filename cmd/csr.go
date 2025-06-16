package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
)

func ExecuteCsrCommand(arg []string, csrFlagSet *flag.FlagSet) {

	// Parse argument flags
	csrPath := csrFlagSet.String("csr", "-", "Output filepath for the certificate sign request")
	commonName := csrFlagSet.String("cn", "", "Subject Common Name for the certificate")
	dnsarg := csrFlagSet.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := csrFlagSet.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := csrFlagSet.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := csrFlagSet.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	csrFlagSet.Parse(arg)

	privateKey, err := certificate.GenerateKey("RSA")
	if err != nil {
		log.Fatalf("failed to generate a key: %s", err)
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
				log.Fatalf("invalid uri [%s]: %s", v, err)
				return
			}
			sanuri = append(sanuri, uri)
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: *commonName,
		},
		DNSNames:       sandns,
		EmailAddresses: sanemail,
		IPAddresses:    sanip,
		URIs:           sanuri,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		log.Fatalf("failed to create csr: %w", err)
		return
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}

	switch *csrPath {
	case "-":
		fmt.Printf("%s", pem.EncodeToMemory(csrPEM))
	default:
		err = certificate.WritePem(csrPEM, *csrPath)
		if err != nil {
			log.Fatalf("failed to save x.509 certificate signing request to %s: %s", *csrPath, err)
			return
		}
	}
}
