package main

import (
	"bufio"
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

var testCommandInputReader io.Reader = os.Stdin

func ExecuteTestCommand(arg []string, testFlagSet *flag.FlagSet, cfg *appconfig.Settings) {
	if err := executeTestCommand(arg, testFlagSet, os.Stdout, cfg); err != nil {
		fmt.Fprintf(os.Stdout, "%v\n", err)
		exitFunc(1)
	}
}

func executeTestCommand(arg []string, testFlagSet *flag.FlagSet, stdout io.Writer, cfg *appconfig.Settings) error {
	// Parse argument flags
	signerName := testFlagSet.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")")
	endpoint := testFlagSet.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caEndpoint := testFlagSet.String("ca-endpoint", cfg.CAEndpoint, "Target destination API endpoint to retrieve the signer-issued CA certificate (leave it empty to use default)")
	signerTLSCAPath := testFlagSet.String("signer-tls-ca", defaultString(cfg.SignerTLSCAPath, signer.DefaultSignerTLSCAPath()), "Local PEM path for the CA used to verify the signer server TLS certificate")
	commonName := testFlagSet.String("cn", "", "Subject Common Name for the test certificate (default: \"<athenz user prefix>.<oauth user name>\")")
	userNameClaim := testFlagSet.String("claim", defaultString(cfg.UserClaim, oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM), "JWT Claim Name to extract the user name")
	userName := testFlagSet.String("username", "", "OIDC user name for password grant")
	passwordStdin := testFlagSet.Bool("password-stdin", false, "Read the OIDC password for password grant from stdin")

	debug := testFlagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	testFlagSet.SetOutput(stdout)
	if err := testFlagSet.Parse(arg); err != nil {
		return err
	}

	resolveSignerEndpoints(signerName, endpoint, caEndpoint)
	applySignerTLSCAPath(signerTLSCAPath)
	if *debug {
		fmt.Fprintf(stdout, "Signer URL is set as:%s\n", *endpoint)
		fmt.Fprintf(stdout, "Signer CA endpoint is set as:%s\n", *caEndpoint)
		fmt.Fprintf(stdout, "Signer TLS CA path is set as:%s\n", *signerTLSCAPath)
	}

	switch *signerName {
	case "crypki":
		accessToken, err := getTestAccessToken(*userName, *passwordStdin, debug)
		if err != nil {
			return err
		}
		if *debug {
			fmt.Fprintf(stdout, "Access Token retrieved Successfully:\n%s\n", accessToken)
		}
		if *commonName == "" {
			username, err := getUserNameFromAccessToken(accessToken, *userNameClaim)
			if err != nil {
				return fmt.Errorf("Failed to extract Athenz User Name from Access Token: %v", err)
			}
			*commonName = certificate.DEFAULT_ATHENZ_USER_PREFIX + username
			if *debug {
				fmt.Fprintf(stdout, "Athenz User Name is: %s\n", *commonName)
			}
		}
		csr, err := buildTestCSR(commonName)
		if err != nil {
			return err
		}
		err, _ = sendCrypkiCSR(*endpoint, csr, &map[string][]string{
			"Authorization": {"Bearer " + accessToken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		err, _ = getCrypkiRootCA(false, *caEndpoint, &map[string][]string{
			"Authorization": {"Bearer " + accessToken},
		})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	case "cfssl":
		err, _ := getCFSSLRootCA(true, *caEndpoint, &map[string][]string{})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	case "zts":
		accessToken, err := getTestAccessToken(*userName, *passwordStdin, debug)
		if err != nil {
			return err
		}
		if *debug {
			fmt.Fprintf(stdout, "Access Token retrieved Successfully:\n%s\n", accessToken)
		}
		if *commonName == "" {
			username, err := getUserNameFromAccessToken(accessToken, *userNameClaim)
			if err != nil {
				return fmt.Errorf("Failed to extract Athenz User Name from Access Token: %v", err)
			}
			*commonName = certificate.DEFAULT_ATHENZ_USER_PREFIX + username
			if *debug {
				fmt.Fprintf(stdout, "Athenz User Name is: %s\n", *commonName)
			}
		}
		csr, err := buildTestCSR(commonName)
		if err != nil {
			return err
		}
		err, _ = sendZTSCSR(*commonName, *endpoint, csr, accessToken, *signerTLSCAPath, nil)
		if err != nil {
			return fmt.Errorf("Failed to get signed certificate: %v", err)
		}
		err, _ = getZTSRootCA(false, *caEndpoint, nil)
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	}
	fmt.Fprintf(stdout, "%s test complete\n", DEFAULT_APP_NAME)
	return nil
}

func getTestAccessToken(userName string, passwordStdin bool, debug *bool) (string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return "", fmt.Errorf("username is required for test signer flow (set -username)")
	}

	password, err := getTestPassword(passwordStdin)
	if err != nil {
		return "", err
	}
	accessToken, err := getPasswordGrantAccessToken(userName, password, debug)
	if err != nil {
		return "", fmt.Errorf("Failed to get access token: %v", err)
	}
	if accessToken == "" {
		return "", fmt.Errorf("Failed to get access token: empty token")
	}
	return accessToken, nil
}

func getTestPassword(passwordStdin bool) (string, error) {
	if passwordStdin {
		reader := bufio.NewReader(testCommandInputReader)
		password, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("failed to read password from stdin: %v", err)
		}
		password = strings.TrimRight(password, "\r\n")
		if password == "" {
			return "", fmt.Errorf("password is required for test signer flow")
		}
		return password, nil
	}

	if !passwordStdin {
		return "", fmt.Errorf("password is required for test signer flow (use -password-stdin)")
	}
	return "", fmt.Errorf("password is required for test signer flow")
}

func buildTestCSR(commonName *string) (string, error) {
	empty := ""
	err, _, csrPEM := generateCSR("", commonName, &empty, &empty, &empty, &empty)
	if err != nil {
		return "", fmt.Errorf("Failed to generate csr: %v", err)
	}
	return strings.TrimSuffix(string(pem.EncodeToMemory(csrPEM)), "\n"), nil
}
