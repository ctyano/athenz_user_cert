package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ctyano/athenz_user_cert/pkg/certificate"
	"github.com/ctyano/athenz_user_cert/pkg/oidc"
	"github.com/ctyano/athenz_user_cert/pkg/signer"
)

var (
	DEFAULT_APP_NAME = "athenz_user_cert"
	SIGNER_NAME      = "crypki"
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
	signerURL := flag.String("url", "http://localhost:10000/v3/sig/x509-cert/keys/x509-key", "Target destination URL for the certificate sign request")

	commonName := flag.String("cn", "", "Subject Common Name for the user certificate (default: <athenz user prefix>.<oauth user name>)")

	dnsarg := flag.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := flag.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := flag.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := flag.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	signerName := flag.String("signer", SIGNER_NAME, "Name for the certificate signer product(crypki or cfssl)")
	debug := flag.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	responseMode := flag.String("response-mode", "query", "OAuth2 response_mode (query or form_post)")

	flag.Parse()

	accesstoken, err := oidc.GetAuthAccessToken(responseMode)
	if err != nil {
		log.Fatalf("Failed to get access token: %v\n", err)
		return
	}
	if *debug {
		log.Printf("Access Token: %v\n", accesstoken)
	}

	if *commonName == "" {
		*commonName = certificate.DEFAULT_ATHENZ_USER_PREFIX + oidc.GetUserNameFromAccessToken(accesstoken)
	}

	err, key, csrPEM := certificate.GenerateCSR("", commonName, dnsarg, emailarg, iparg, uriarg)
	if err != nil {
		log.Fatalf("Failed to generate csr: %v\n", err)
		return
	}
	csr := string(pem.EncodeToMemory(csrPEM))
	if *debug {
		log.Printf("Generated csr: %s\n", csr)
	}

	var cert string
	switch *signerName {
	case "crypki":
		err, cert = signer.SendCrypkiCSR(*signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			log.Fatalf("Failed to send csr: %v\n", err)
			return
		}
		if *debug {
			log.Printf("Signed cert: %s\n", cert)
		}
	case "cfssl":
	}

	keyPEM, err := certificate.PrivateKeyToPEM(*key)
	if err != nil {
		log.Fatalf("Failed to convert x.509 certificate key to PEM string: %v", err)
		return
	}
	keyDestination := certificate.UserKeyPath()
	err = certificate.WritePEM(keyPEM, keyDestination)
	if err != nil {
		log.Fatalf("Failed to save x.509 certificate key to %s: %v", keyDestination, err)
		return
	}

	certDestination := certificate.UserCertPath()
	err = ioutil.WriteFile(certDestination, []byte(cert), 0600)
	if err != nil {
		log.Fatalf("Failed to save x.509 certificate to %s: %v", certDestination, err)
		return
	}
}
