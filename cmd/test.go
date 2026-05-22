package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
)

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
	caURL := testFlagSet.String("ca", cfg.CAURL, "Target destination URL or local PEM path to retrieve the CA certificate (leave it empty to use default)")

	debug := testFlagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	testFlagSet.Parse(arg)

	resolveSignerEndpointCA(signerName, endpoint, caURL)
	if *debug {
		fmt.Fprintf(stdout, "Signer URL is set as:%s\n", *endpoint)
		fmt.Fprintf(stdout, "Signer CA URL is set as:%s\n", *caURL)
	}
	switch *signerName {
	case "crypki":
		err, _ := getCrypkiRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	case "cfssl":
		err, _ := getCFSSLRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	case "zts":
		err, _ := getZTSRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			return fmt.Errorf("Failed to get ca certificate: %v", err)
		}
	}
	fmt.Fprintf(stdout, "%s test complete\n", DEFAULT_APP_NAME)
	return nil
}
