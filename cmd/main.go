package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io"
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

	loadConfig                         = appconfig.Load
	getAuthAttestationData             = oidc.GetAuthAttestationData
	getAuthAttestationDataAndAccessTok = oidc.GetAuthAttestationDataAndAccessToken
	getAuthAccessToken                 = oidc.GetAuthAccessToken
	getUserNameFromAccessToken         = oidc.GetUserNameFromAccessToken
	generateCSR                        = certificate.GenerateCSR
	privateKeyToPEM                    = certificate.PrivateKeyToPEM
	writePEMFile                       = certificate.WritePEM
	userKeyPath                        = certificate.UserKeyPath
	userCertPath                       = certificate.UserCertPath
	caCertPath                         = certificate.CACertPath
	writeOutputFile                    = os.WriteFile
	sendCrypkiCSR                      = signer.SendCrypkiCSR
	getCrypkiRootCA                    = signer.GetCrypkiRootCA
	sendCFSSLCSR                       = signer.SendCFSSLCSR
	getCFSSLRootCA                     = signer.GetCFSSLRootCA
	sendZTSCSR                         = signer.SendZTSCSR
	getZTSRootCA                       = signer.GetZTSRootCA
)

func main() {
	cfg, loadErr := loadConfig()
	if loadErr != nil {
		fmt.Printf("Failed to load configuration: %s\n", loadErr)
		os.Exit(1)
	}

	if err := execute(os.Args[1:], os.Stdout, cfg); err != nil {
		fmt.Fprintln(os.Stdout, err)
		os.Exit(1)
	}
}

func execute(args []string, stdout io.Writer, cfg *appconfig.Settings) error {
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

	if len(args) > 0 {
		switch {
		case strings.HasSuffix(args[0], "version"):
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(args[1:], versionFlagSet)
			return nil
		case strings.HasSuffix(args[0], "test"):
			testFlagSet := flag.NewFlagSet("test", flag.ExitOnError)
			ExecuteTestCommand(args[1:], testFlagSet, cfg)
			return nil
		case strings.HasSuffix(args[0], "help"):
			fmt.Fprintln(stdout, usage)
			flagSet := flag.NewFlagSet(appname, flag.ContinueOnError)
			flagSet.SetOutput(stdout)
			addCommandFlags(flagSet, cfg)
			flagSet.PrintDefaults()
			return nil
		}
	}

	// Parse argument flags
	flagSet := flag.NewFlagSet(appname, flag.ContinueOnError)
	flagSet.SetOutput(stdout)
	signerName, endpoint, caURL, commonName, userNameClaim, dnsarg, emailarg, iparg, uriarg, debug, responseMode := addCommandFlags(flagSet, cfg)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	var accesstoken, attestationData string
	var err error
	switch *signerName {
	case "zts":
		if *commonName == "" {
			attestationData, accesstoken, err = getAuthAttestationDataAndAccessTok(responseMode, debug)
			if err != nil || accesstoken == "" || attestationData == "" {
				return fmt.Errorf("Failed to get OIDC authentication data: %v", err)
			}
		} else {
			attestationData, err = getAuthAttestationData(responseMode, debug)
			if err != nil || attestationData == "" {
				return fmt.Errorf("Failed to get OIDC attestation data: %v", err)
			}
		}
	default:
		accesstoken, err = getAuthAccessToken(responseMode, debug)
		if err != nil || accesstoken == "" {
			return fmt.Errorf("Failed to get access token: %v", err)
		}
	}
	if *debug {
		if accesstoken != "" {
			fmt.Fprintf(stdout, "Access Token retrieved Successfully:\n%s\n", accesstoken)
		}
		if attestationData != "" {
			fmt.Fprintf(stdout, "OIDC attestation data:\n%s\n", attestationData)
		}
	}

	if *commonName == "" {
		username, err := getUserNameFromAccessToken(accesstoken, *userNameClaim)
		if err != nil {
			return fmt.Errorf("Failed to extract Athenz User Name from Access Token: %v", err)
		}
		*commonName = certificate.DEFAULT_ATHENZ_USER_PREFIX + username
		if *debug {
			fmt.Fprintf(stdout, "Athenz User Name is: %s\n", *commonName)
		}
	}

	err, key, csrPEM := generateCSR("", commonName, dnsarg, emailarg, iparg, uriarg)
	if err != nil {
		return fmt.Errorf("Failed to generate csr: %v", err)
	}
	csr := strings.TrimSuffix(string(pem.EncodeToMemory(csrPEM)), "\n")
	if *debug {
		fmt.Fprintf(stdout, "Generated csr:\n%s\n", csr)
	}

	resolveSignerEndpointCA(signerName, endpoint, caURL)
	if *debug {
		fmt.Fprintf(stdout, "Signer URL is set as:%s\n", *endpoint)
		fmt.Fprintf(stdout, "Signer CA URL is set as:%s\n", *caURL)
	}

	var cert, cacert string
	switch *signerName {
	case "crypki":
		err, cert = sendCrypkiCSR(*endpoint, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getCrypkiRootCA(false, *caURL, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "cfssl":
		err, cert = sendCFSSLCSR(*endpoint, csr, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getCFSSLRootCA(false, *caURL, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "zts":
		err, cert = sendZTSCSR(*commonName, *endpoint, csr, attestationData, *caURL, nil)
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getZTSRootCA(false, *caURL, nil)
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	}

	keyPEM, err := privateKeyToPEM(*key)
	if err != nil {
		return fmt.Errorf("Failed to convert X.509 certificate key to PEM string: %v", err)
	}
	keyDestination := userKeyPath()
	err = writePEMFile(keyPEM, keyDestination)
	if err != nil {
		return fmt.Errorf("Failed to save X.509 certificate key to %s: %v", keyDestination, err)
	}

	certDestination := userCertPath()
	err = writeOutputFile(certDestination, []byte(cert), 0600)
	if err != nil {
		return fmt.Errorf("Failed to save X.509 certificate to %s: %v", certDestination, err)
	}
	caCertDestination := caCertPath()

	if cacert != "" {
		err = writeOutputFile(caCertDestination, []byte(cacert), 0600)
		if err != nil {
			return fmt.Errorf("Failed to save X.509 CA certificate to %s: %v", caCertDestination, err)
		}
	}

	fmt.Fprintf(stdout, "Signed Athenz User certificate key is successfully stored at: \t%s\n", keyDestination)
	fmt.Fprintf(stdout, "Signed Athenz User certificate is successfully stored at: \t%s\n", certDestination)
	if cacert != "" {
		fmt.Fprintf(stdout, "Signed Athenz CA certificate is successfully stored at: \t%s\n", caCertDestination)
	} else {
		fmt.Fprintf(stdout, "Signed Athenz CA certificate was not updated. Use -ca with a local PEM path or CA endpoint if you need to refresh %s\n", caCertDestination)
	}

	return nil
}

func addCommandFlags(flagSet *flag.FlagSet, cfg *appconfig.Settings) (signerName, endpoint, caURL, commonName, userNameClaim, dnsarg, emailarg, iparg, uriarg *string, debug *bool, responseMode *string) {
	signerName = flagSet.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")")
	endpoint = flagSet.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caURL = flagSet.String("ca", cfg.CAURL, "Target destination URL or local PEM path to retrieve the CA certificate (leave it empty to use default)")

	commonName = flagSet.String("cn", "", "Subject Common Name for the user certificate (default: \"<athenz user prefix>.<oauth user name>\")")
	userNameClaim = flagSet.String("claim", defaultString(cfg.UserClaim, oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM), "JWT Claim Name to extract the user name")

	dnsarg = flagSet.String("dns", "", "Comma-separated SANs(Subject Alternative Names) as hostnames for the certificate")
	emailarg = flagSet.String("email", "", "Comma-separated SANs(Subject Alternative Names) as Emails for the certificate")
	iparg = flagSet.String("ip", "", "Comma-separated SANs(Subject Alternative Names) as IPs for the certificate")
	uriarg = flagSet.String("uri", "", "Comma-separated SANs(Subject Alternative Names) as URIs for the certificate")

	debug = flagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	responseMode = flagSet.String("response-mode", defaultString(cfg.ResponseMode, "form_post"), "OAuth2 response_mode (\"query\" or \"form_post\")")
	return
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
