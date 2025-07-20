package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ctyano/athenz_user_cert/pkg/certificate"
	"github.com/ctyano/athenz_user_cert/pkg/oidc"
	"github.com/ctyano/athenz_user_cert/pkg/signer"
)

var (
	DEFAULT_APP_NAME    = "athenz_user_cert"
	DEFAULT_SIGNER_NAME = "crypki"
)

func main() {
	appname := DEFAULT_APP_NAME
	var defaultSignerURL string
	switch DEFAULT_SIGNER_NAME {
	case "crypki":
		defaultSignerURL = signer.DEFAULT_SIGNER_CRYPKI_URL
	case "cfssl":
		defaultSignerURL = signer.DEFAULT_SIGNER_CFSSL_URL
	}

	// Parse argument flags
	signerURL := flag.String("url", defaultSignerURL, "Target destination URL for the certificate sign request")

	commonName := flag.String("cn", "", "Subject Common Name for the user certificate (default: \"<athenz user prefix>.<oauth user name>\")")
	userNameClaim := flag.String("claim", oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM, "JWT Claim Name to extract the user name")

	dnsarg := flag.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := flag.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := flag.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := flag.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	signerName := flag.String("signer", DEFAULT_SIGNER_NAME, "Name for the certificate signer product (\"crypki\" or \"cfssl\")")
	debug := flag.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	responseMode := flag.String("response-mode", "form_post", "OAuth2 response_mode (\"query\" or \"form_post\")")

	flag.Parse()

	if len(os.Args) == 2 {
		usage := fmt.Sprintf(`Usage of %s:
  Generate certificate signing request and send the csr to the server.
  Authenticate user with Open ID Connect protocol and retrieve OAuth Access Token.

Subcommands:
  version:
  	Print the version and the pre desined parameters of this CLI.
  help:
  	Print this help message.

Options:
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

	accesstoken, err := oidc.GetAuthAccessToken(responseMode, debug)
	if err != nil || accesstoken == "" {
		fmt.Printf("Failed to get access token: %v\n", err)
		os.Exit(1)
	}
	if *debug {
		fmt.Printf("Access Token retrieved Successfully: %v\n", accesstoken)
	}

	if *commonName == "" {
		username, err := oidc.GetUserNameFromAccessToken(accesstoken, *userNameClaim)
		if err != nil {
			fmt.Printf("Failed to extract Athenz User Name from Access Token: %s\n", err)
			os.Exit(1)
		}
		*commonName = certificate.DEFAULT_ATHENZ_USER_PREFIX + username
		if *debug {
			fmt.Printf("Athenz User Name is: %s\n", *commonName)
		}
	}

	err, key, csrPEM := certificate.GenerateCSR("", commonName, dnsarg, emailarg, iparg, uriarg)
	if err != nil {
		fmt.Printf("Failed to generate csr: %v\n", err)
		os.Exit(1)
	}
	csr := strings.TrimSuffix(string(pem.EncodeToMemory(csrPEM)), "\n")
	if *debug {
		fmt.Printf("Generated csr: %s\n", csr)
	}

	var cert string
	switch *signerName {
	case "crypki":
		err, cert = signer.SendCrypkiCSR(*signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %v\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate: %s\n", cert)
		}
	case "cfssl":
		err, cert = signer.SendCFSSLCSR(*signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %v\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate: %s\n", cert)
		}
	}

	keyPEM, err := certificate.PrivateKeyToPEM(*key)
	if err != nil {
		fmt.Printf("Failed to convert x.509 certificate key to PEM string: %v", err)
		os.Exit(1)
	}
	keyDestination := certificate.UserKeyPath()
	err = certificate.WritePEM(keyPEM, keyDestination)
	if err != nil {
		fmt.Printf("Failed to save x.509 certificate key to %s: %v", keyDestination, err)
		os.Exit(1)
	}

	certDestination := certificate.UserCertPath()
	err = ioutil.WriteFile(certDestination, []byte(cert), 0600)
	if err != nil {
		fmt.Printf("Failed to save x.509 certificate to %s: %v", certDestination, err)
		os.Exit(1)
	}

	fmt.Printf("Signed Athenz User certificate key is successfully stored at: %s\n", keyDestination)
	fmt.Printf("Signed Athenz User certificate is successfully stored at: %s\n", certDestination)
}
