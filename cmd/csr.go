package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	"github.com/ctyano/athenz-user-cert/pkg/http"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
)

func ExecuteCsrCommand(arg []string, csrFlagSet *flag.FlagSet) {

	// Parse argument flags
	csrDestination := csrFlagSet.String("csr", "https://crypki-softhsm.crypki/v3/sig/x509-cert/keys/x509-key", "Target destination for the certificate sign request")
	commonName := csrFlagSet.String("cn", "", "Subject Common Name for the certificate")
	dnsarg := csrFlagSet.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := csrFlagSet.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := csrFlagSet.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := csrFlagSet.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	csrFlagSet.Parse(arg)

	err, csrPEM := certificate.GenerateCSR(http.DEFAULT_X509_ALGORITHM, commonName, dnsarg, emailarg, iparg, uriarg)

	switch {
	case strings.HasPrefix(*csrDestination, "https://") || strings.HasPrefix(*csrDestination, "http://"):
		at := oidc.NewAccessToken(true) // debug: true
		accesstoken, err := at.GetAuthAccessToken()
		if err != nil {
			log.Fatalf("failed to get access token: %v\n", err)
			return
		}
		log.Printf("access token: %v\n", accesstoken)
		err = http.SendCSR(*csrDestination, string(pem.EncodeToMemory(csrPEM)), &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			log.Fatalf("failed to send csr: %v\n", err)
			return
		}
	case *csrDestination == "-":
		fmt.Printf("%s", pem.EncodeToMemory(csrPEM))
	default:
		err = certificate.WritePem(csrPEM, *csrDestination)
		if err != nil {
			log.Fatalf("failed to save x.509 certificate signing request to %s: %s", *csrDestination, err)
			return
		}
	}
}
