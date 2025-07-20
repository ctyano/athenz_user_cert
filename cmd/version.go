package main

import (
	"flag"
	"fmt"

	"github.com/ctyano/athenz_user_cert/pkg/oidc"
	"github.com/ctyano/athenz_user_cert/pkg/signer"
)

var (
	VERSION    = "v0.0.0"
	BUILD_DATE = "1970/01/01"
)

func ExecuteVersionCommand(arg []string, versionFlagSet *flag.FlagSet) {

	// Parse argument flags
	versionFlagSet.Parse(arg)

	fmt.Printf("CLI basic configuration:\n")
	fmt.Printf("  CLI built date: %s\n", BUILD_DATE)
	fmt.Printf("  CLI version: %s\n", VERSION)

	fmt.Printf("CLI Open ID configuration:\n")
	fmt.Printf("  CLI Open ID Connect Issuer: %s\n", oidc.DEFAULT_OIDC_ISSUER)
	fmt.Printf("  CLI Open ID Connect Client ID: %s\n", oidc.DEFAULT_OIDC_CLIENT_ID)
	fmt.Printf("  CLI Open ID Connect Scopes: %s\n", oidc.DEFAULT_OIDC_SCOPES)
	fmt.Printf("  CLI Open ID Connect Client Listening Address: %s\n", oidc.DEFAULT_OIDC_LISTEN_ADDRESS)
	fmt.Printf("  CLI Open ID Connect Access Token Stored Path: $HOME/%s\n", oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH)
	fmt.Printf("  CLI Open ID Connect Access Token Validity: %s minutes\n", oidc.DEFAULT_OIDC_ACCESS_TOKEN_VALIDITY)
	fmt.Printf("  CLI Open ID Connect Access Token User Name JWT Claim: %s\n", oidc.DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM)

	fmt.Printf("CLI X.509 configuration:\n")
	fmt.Printf("  CLI X.509 configuration for Crypki:\n")
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_CRYPKI_URL)
	fmt.Printf("    CLI X.509 Certificate Validity: %s seconds\n", signer.DEFAULT_SIGNER_CRYPKI_VALIDITY)
	fmt.Printf("    CLI X.509 Certificate Identifier: %s\n", signer.DEFAULT_SIGNER_CRYPKI_IDENTIFIER)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_CRYPKI_TIMEOUT)
	fmt.Printf("  CLI X.509 configuration for CFSSL:\n")
	fmt.Printf("    CLI X.509 Certificate Signer URL: %s\n", signer.DEFAULT_SIGNER_CFSSL_URL)
	fmt.Printf("    CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_SIGNER_CFSSL_TIMEOUT)
}
