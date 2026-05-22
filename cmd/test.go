package main

import (
	"flag"
	"fmt"
	"os"

	appconfig "github.com/ctyano/athenz-user-cert/pkg/config"
	"github.com/ctyano/athenz-user-cert/pkg/signer"
)

func ExecuteTestCommand(arg []string, testFlagSet *flag.FlagSet, cfg *appconfig.Settings) {

	// Parse argument flags
	signerName := testFlagSet.String("signer", defaultString(cfg.SignerName, DEFAULT_SIGNER_NAME), "Name for the certificate signer product (\"crypki\", \"cfssl\" or \"zts\")")
	endpoint := testFlagSet.String("endpoint", cfg.Endpoint, "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caURL := testFlagSet.String("ca", cfg.CAURL, "Target destination URL or local PEM path to retrieve the CA certificate (leave it empty to use default)")

	debug := testFlagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	testFlagSet.Parse(arg)

	resolveSignerEndpointCA(signerName, endpoint, caURL)
	if *debug {
		fmt.Printf("Signer URL is set as:%s\n", *endpoint)
		fmt.Printf("Signer CA URL is set as:%s\n", *caURL)
	}
	switch *signerName {
	case "crypki":
		err, _ := signer.GetCrypkiRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
	case "cfssl":
		err, _ := signer.GetCFSSLRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
	case "zts":
		err, _ := signer.GetZTSRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s test complete\n", DEFAULT_APP_NAME)
}
