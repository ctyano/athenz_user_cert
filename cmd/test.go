package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ctyano/athenz_user_cert/pkg/signer"
)

func ExecuteTestCommand(arg []string, testFlagSet *flag.FlagSet) {

	// Parse argument flags
	signerName := testFlagSet.String("signer", DEFAULT_SIGNER_NAME, "Name for the certificate signer product (\"crypki\" or \"cfssl\")")
	signerURL := flag.String("sign-url", "", "Target destination URL to send the certificate sign request (leave it empty to use default)")
	caURL := flag.String("ca-url", "", "Target destination URL to retrieve the ca certificate (leave it empty to use default)")

	debug := testFlagSet.Bool("debug", false, "Print the access token to send the Certificate Siginig Request")

	testFlagSet.Parse(arg)

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
	case "vault":
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
	case "vault":
		err, _ := signer.GetVaultRootCA(true, *caURL, &map[string][]string{})
		if err != nil {
			fmt.Printf("Failed to get ca certificate: %s\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("%s test complete\n", DEFAULT_APP_NAME)
}
