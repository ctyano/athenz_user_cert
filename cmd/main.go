package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
	"github.com/ctyano/athenz-user-cert/pkg/oidc"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

var (
	DEFAULT_APP_NAME    = "athenzusercert"
	DEFAULT_SIGNER_NAME = "zts"
)

func main() {
	appname := DEFAULT_APP_NAME
	cfg, loadErr := appconfig.Load()
	if loadErr != nil {
		fmt.Printf("Failed to load configuration: %s\n", loadErr)
		os.Exit(1)
	}

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
			ExecuteTestCommand(os.Args[2:], testFlagSet, cfg)
			return
		case strings.HasSuffix(os.Args[1], "help"):
			fmt.Println(usage)
			flag.PrintDefaults()
			return
		}
	}

	// Parse argument flags
	signerName := flag.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")")
	endpoint := flag.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caURL := flag.String("ca", cfg.CAURL, "Target destination URL or local PEM path to retrieve the CA certificate (leave it empty to use default)")

	commonName := flag.String("cn", "", "Subject Common Name for the user certificate (default: \"<athenz user prefix>.<oauth user name>\")")
	userNameClaim := flag.String("claim", defaultString(cfg.UserClaim, oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM), "JWT Claim Name to extract the user name")

	dnsarg := flag.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg := flag.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg := flag.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg := flag.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	debug := flag.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	responseMode := flag.String("response-mode", defaultString(cfg.ResponseMode, "form_post"), "OAuth2 response_mode (\"query\" or \"form_post\")")

	flag.Parse()

	var accesstoken, attestationData string
	var err error
	switch *signerName {
	case "zts":
		if *commonName == "" {
			attestationData, accesstoken, err = oidc.GetAuthAttestationDataAndAccessToken(responseMode, debug)
			if err != nil || accesstoken == "" || attestationData == "" {
				fmt.Printf("Failed to get OIDC authentication data: %s\n", err)
				os.Exit(1)
			}
		} else {
			attestationData, err = oidc.GetAuthAttestationData(responseMode, debug)
			if err != nil || attestationData == "" {
				fmt.Printf("Failed to get OIDC attestation data: %s\n", err)
				os.Exit(1)
			}
		}
	default:
		accesstoken, err = oidc.GetAuthAccessToken(responseMode, debug)
		if err != nil || accesstoken == "" {
			fmt.Printf("Failed to get access token: %s\n", err)
			os.Exit(1)
		}
	}
	if *debug {
		if accesstoken != "" {
			fmt.Printf("Access Token retrieved Successfully:\n%s\n", accesstoken)
		}
		if attestationData != "" {
			fmt.Printf("OIDC attestation data:\n%s\n", attestationData)
		}
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

	resolveSignerEndpointCA(signerName, endpoint, caURL)
	if *debug {
		fmt.Printf("Signer URL is set as:%s\n", *endpoint)
		fmt.Printf("Signer CA URL is set as:%s\n", *caURL)
	}

	var cert, cacert string
	switch *signerName {
	case "crypki":
		err, cert = signer.SendCrypkiCSR(*endpoint, csr, &map[string][]string{
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
		err, cert = signer.SendCFSSLCSR(*endpoint, csr, &map[string][]string{
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
	case "zts":
		err, cert = signer.SendZTSCSR(*commonName, *endpoint, csr, attestationData, *caURL, nil)
		if err != nil {
			fmt.Printf("Failed to get signed certificate: %s\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Signed certificate:\n%s\n", cert)
		}
		err, cacert = signer.GetZTSRootCA(false, *caURL, nil)
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

	if cacert != "" {
		err = os.WriteFile(caCertDestination, []byte(cacert), 0600)
		if err != nil {
			fmt.Printf("Failed to save X.509 CA certificate to %s: %s", caCertDestination, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Signed Athenz User certificate key is successfully stored at: \t%s\n", keyDestination)
	fmt.Printf("Signed Athenz User certificate is successfully stored at: \t%s\n", certDestination)
	if cacert != "" {
		fmt.Printf("Signed Athenz CA certificate is successfully stored at: \t%s\n", caCertDestination)
	} else {
		fmt.Printf("Signed Athenz CA certificate was not updated. Use -ca with a local PEM path or CA endpoint if you need to refresh %s\n", caCertDestination)
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func resolveSignerEndpointCA(signerName, endpoint, caURL *string) {
	switch *signerName {
	case "crypki":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_CRYPKI_CA_URL
		}
	case "cfssl":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_CFSSL_CA_URL
		}
	case "zts":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_ZTS_SIGN_URL
		}
		if *caURL == "" {
			*caURL = signer.DEFAULT_SIGNER_ZTS_CA_URL
		}
	}
}
