package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	"github.com/ctyano/athenz-user-cert/pkg/http"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
)

var (
	DEFAULT_APP_NAME = "athenz-user-cert"
)

func main() {
	appname := DEFAULT_APP_NAME

	if len(os.Args) == 2 {
		usage := fmt.Sprintf(`Usage of %s:
  Generate certificate signing request and send the csr to the server.
  Authenticate user with Open ID Connect protocol and retrieve OAuth Access Token.

  Subcommands:
    version:
    	Print the version and the pre desined parameters of this CLI.
`, appname)
		switch {
		case strings.HasSuffix(os.Args[1], "version"):
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(os.Args[2:], versionFlagSet)
			return
		case strings.HasSuffix(os.Args[1], "help"):
			fmt.Printf(usage)
			flag.PrintDefaults()
			return
		}
	}

	// Parse argument flags
	csrDestination := flag.String("csr", "https://certsigner-envoy.athenz/v3/sig/x509-cert/keys/x509-key", "Target destination for the certificate sign request")
	commonName := flag.String("cn", "", "Subject Common Name for the certificate")
	dnsarg := flag.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := flag.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := flag.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := flag.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")
	debug := flag.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	flag.Parse()

	err, csrPEM := certificate.GenerateCSR(http.DEFAULT_X509_ALGORITHM, commonName, dnsarg, emailarg, iparg, uriarg)

	switch {
	case strings.HasPrefix(*csrDestination, "https://") || strings.HasPrefix(*csrDestination, "http://"):
		accesstoken, err := oidc.GetAuthAccessToken()
		if err != nil {
			log.Fatalf("Failed to get access token: %v\n", err)
			return
		}
		if *debug {
			log.Printf("Access Token: %v\n", accesstoken)
		}
		err = http.SendCSR(*csrDestination, string(pem.EncodeToMemory(csrPEM)), &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			log.Fatalf("Failed to send csr: %v\n", err)
			return
		}
	case *csrDestination == "-":
		fmt.Printf("%s", pem.EncodeToMemory(csrPEM))
	default:
		err = certificate.WritePem(csrPEM, *csrDestination)
		if err != nil {
			log.Fatalf("Failed to save x.509 certificate signing request to %s: %s", *csrDestination, err)
			return
		}
	}
}
