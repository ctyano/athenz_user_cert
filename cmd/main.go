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

	loadConfig                  = appconfig.Load
	getAuthAccessToken          = oidc.GetAuthAccessToken
	getPasswordGrantAccessToken = oidc.GetPasswordGrantAccessToken
	getUserNameFromAccessToken  = oidc.GetUserNameFromAccessToken
	generateCSR                 = certificate.GenerateCSR
	privateKeyToPEM             = certificate.PrivateKeyToPEM
	writePEMFile                = certificate.WritePEM
	userKeyPath                 = certificate.UserKeyPath
	userCertPath                = certificate.UserCertPath
	caCertPath                  = certificate.CACertPath
	writeOutputFile             = os.WriteFile
	sendCrypkiCSR               = signer.SendCrypkiCSR
	getCrypkiRootCA             = signer.GetCrypkiRootCA
	sendCFSSLCSR                = signer.SendCFSSLCSR
	getCFSSLRootCA              = signer.GetCFSSLRootCA
	sendZTSCSR                  = signer.SendZTSCSR
	getZTSRootCA                = signer.GetZTSRootCA
	exitFunc                    = os.Exit
)

func main() {
	exitFunc(runMain(os.Args[1:], os.Stdout))
}

func runMain(args []string, stdout io.Writer) int {
	cfg, loadErr := loadConfig()
	if loadErr != nil {
		fmt.Fprintf(stdout, "Failed to load configuration: %s\n", loadErr)
		return 1
	}

	if err := execute(args, stdout, cfg); err != nil {
		fmt.Fprintln(stdout, err)
		return 1
	}
	return 0
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
			return executeTestCommand(args[1:], testFlagSet, stdout, cfg)
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
	signerName, endpoint, caEndpoint, signerTLSCAPath, commonName, userNameClaim, dnsarg, emailarg, iparg, uriarg, debug, responseMode := addCommandFlags(flagSet, cfg)
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	var accesstoken string
	var err error
	accesstoken, err = getAuthAccessToken(responseMode, debug)
	if err != nil || accesstoken == "" {
		return fmt.Errorf("Failed to get access token: %v", err)
	}
	if *debug {
		fmt.Fprintf(stdout, "Access Token retrieved Successfully:\n%s\n", accesstoken)
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

	resolveSignerEndpoints(signerName, endpoint, caEndpoint)
	applySignerTLSCAPath(signerTLSCAPath)
	if *debug {
		fmt.Fprintf(stdout, "Signer URL is set as:%s\n", *endpoint)
		fmt.Fprintf(stdout, "Signer CA endpoint is set as:%s\n", *caEndpoint)
		fmt.Fprintf(stdout, "Signer TLS CA path is set as:%s\n", *signerTLSCAPath)
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
		err, cacert = getCrypkiRootCA(false, *caEndpoint, &map[string][]string{
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
		err, cacert = getCFSSLRootCA(false, *caEndpoint, &map[string][]string{
			"Authorization": []string{"Bearer " + accesstoken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "CA certificate:\n%s\n", cacert)
		}
	case "zts":
		err, cert = sendZTSCSR(*commonName, *endpoint, csr, accesstoken, *signerTLSCAPath, nil)
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		if *debug {
			fmt.Fprintf(stdout, "Signed certificate:\n%s\n", cert)
		}
		err, cacert = getZTSRootCA(false, *caEndpoint, nil)
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
		fmt.Fprintf(stdout, "Signed Athenz CA certificate was not updated. Use -ca-endpoint if you need to refresh %s\n", caCertDestination)
	}

	return nil
}

func addCommandFlags(flagSet *flag.FlagSet, cfg *appconfig.Settings) (signerName, endpoint, caEndpoint, signerTLSCAPath, commonName, userNameClaim, dnsarg, emailarg, iparg, uriarg *string, debug *bool, responseMode *string) {
	signerName = flagSet.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")")
	endpoint = flagSet.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caEndpoint = flagSet.String("ca-endpoint", cfg.CAEndpoint, "Target destination API endpoint to retrieve the signer-issued CA certificate (leave it empty to use default)")
	signerTLSCAPath = flagSet.String("signer-tls-ca", defaultString(cfg.SignerTLSCAPath, signer.DefaultSignerTLSCAPath()), "Local PEM path for the CA used to verify the signer server TLS certificate")

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

func resolveSignerEndpoints(signerName, endpoint, caEndpoint *string) {
	switch *signerName {
	case "crypki":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CRYPKI_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_CRYPKI_CA_URL
		}
	case "cfssl":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_CFSSL_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_CFSSL_CA_URL
		}
	case "zts":
		if *endpoint == "" {
			*endpoint = signer.DEFAULT_SIGNER_ZTS_SIGN_URL
		}
		if *caEndpoint == "" {
			*caEndpoint = signer.DEFAULT_SIGNER_ZTS_CA_URL
		}
	}
}

func applySignerTLSCAPath(signerTLSCAPath *string) {
	signer.DEFAULT_SIGNER_TLS_CA_PATH = strings.TrimSpace(*signerTLSCAPath)
}
