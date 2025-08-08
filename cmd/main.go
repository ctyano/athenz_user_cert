package main

import (
	"encoding/pem"
	"flag"
	"fmt"
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

	if len(os.Args) > 1 {
		switch {
		case strings.HasSuffix(os.Args[1], "version"):
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(os.Args[2:], versionFlagSet)
			return
		case strings.HasSuffix(os.Args[1], "test"):
			testFlagSet := flag.NewFlagSet("test", flag.ExitOnError)
			ExecuteTestCommand(os.Args[2:], testFlagSet)
			return
		case strings.HasSuffix(os.Args[1], "help"):
			fmt.Println(usage)
			flag.PrintDefaults()
			return
		}
	}

	// Parse argument flags
	signerName := flag.String("signer", DEFAULT_SIGNER_NAME, "Name for the certificate signer product (\"crypki\" or \"cfssl\")")
	signerURL := flag.String("sign-url", "", "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caURL := flag.String("ca-url", "", "Target destination URL to retrieve the ca certificate (leave it empty to use default)")

	commonName := flag.String("cn", "", "Subject Common Name for the user certificate (default: \"<athenz user prefix>.<oauth user name>\")")
	userNameClaim := flag.String("claim", oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM, "JWT Claim Name to extract the user name")

	dnsarg := flag.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := flag.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := flag.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := flag.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	debug := flag.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	responseMode := flag.String("response-mode", "form_post", "OAuth2 response_mode (\"query\" or \"form_post\")")

	flag.Parse()

	accesstoken, err := oidc.GetAuthAccessToken(responseMode, debug)
	if err != nil || accesstoken == "" {
		fmt.Printf("Failed to get access token: %s\n", err)
		os.Exit(1)
	}
	if *debug {
		fmt.Printf("Access Token retrieved Successfully:\n%s\n", accesstoken)
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
		fmt.Printf("Failed to generate csr: %s\n", err)
		os.Exit(1)
	}
	csr := strings.TrimSuffix(string(pem.EncodeToMemory(csrPEM)), "\n")
	if *debug {
		fmt.Printf("Generated csr:\n%s\n", csr)
	}

	switch *signerName {
	case "crypki":
		if *signerURL == "" {
			*signerURL = signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_CRYPKI_CA_URL
		}
	case "cfssl":
		if *signerURL == "" {
			*signerURL = signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_CFSSL_CA_URL
		}
	}
	if *debug {
		fmt.Printf("Signer URL is set as:%s\n", *signerURL)
		fmt.Printf("Signer CA URL is set as:%s\n", *caURL)
	}

	var cert, cacert string
	switch *signerName {
	case "crypki":
		err, cert = signer.SendCrypkiCSR(*signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate:\n%s\n", cert)
		}
		err, cacert = signer.GetCrypkiRootCA(false, *caURL, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("CA certificate:\n%s\n", cacert)
		}
	case "cfssl":
		err, cert = signer.SendCFSSLCSR(*signerURL, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate:\n%s\n", cert)
		}
		err, cacert = signer.GetCFSSLRootCA(false, *caURL, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("CA certificate:\n%s\n", cacert)
		}
	}

	keyPEM, err := certificate.PrivateKeyToPEM(*key)
	if err != nil {
		fmt.Printf("Failed to convert X.509 certificate key to PEM string: %s", err)
		os.Exit(1)
	}
	keyDestination := certificate.UserKeyPath()
	err = certificate.WritePEM(keyPEM, keyDestination)
	if err != nil {
		fmt.Printf("Failed to save X.509 certificate key to %s: %s", keyDestination, err)
		os.Exit(1)
	}

	certDestination := certificate.UserCertPath()
	err = os.WriteFile(certDestination, []byte(cert), 0600)
	if err != nil {
		fmt.Printf("Failed to save X.509 certificate to %s: %s", certDestination, err)
		os.Exit(1)
	}
	caCertDestination := certificate.CACertPath()
	err = os.WriteFile(caCertDestination, []byte(cacert), 0600)
	if err != nil {
		fmt.Printf("Failed to save X.509 CA certificate to %s: %s", caCertDestination, err)
		os.Exit(1)
	}

	fmt.Printf("Signed Athenz User certificate key is successfully stored at: \t%s\n", keyDestination)
	fmt.Printf("Signed Athenz User certificate is successfully stored at: \t%s\n", certDestination)
	fmt.Printf("Signed Athenz CA certificate is successfully stored at: \t%s\n", caCertDestination)
}
