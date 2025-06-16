package main

import (
	"flag"
	"fmt"
	"strings"

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

	fmt.Printf("CLI built date: %s\n", BUILD_DATE)
	fmt.Printf("CLI version: %s\n", VERSION)

	var masked_client_secret string
	if len(oidc.DEFAULT_OIDC_CLIENT_SECRET) > 2 {
		masked_client_secret = oidc.DEFAULT_OIDC_CLIENT_SECRET[:3] + strings.Repeat("*", len(oidc.DEFAULT_OIDC_CLIENT_SECRET)-3)
	} else {
		masked_client_secret = "***"
	}

	fmt.Printf("CLI Open ID Connect Issuer: %s\n", oidc.DEFAULT_OIDC_ISSUER)
	fmt.Printf("CLI Open ID Connect Client ID: %s\n", oidc.DEFAULT_OIDC_CLIENT_ID)
	fmt.Printf("CLI Open ID Connect Client Secret: %s\n", masked_client_secret)
	fmt.Printf("CLI Open ID Connect Scopes: %s\n", oidc.DEFAULT_OIDC_SCOPES)
	fmt.Printf("CLI Open ID Connect Client Listening Address: %s\n", oidc.DEFAULT_OIDC_LISTEN_ADDRESS)
	fmt.Printf("CLI Open ID Connect Access Token Stored Path: $HOME/%s\n", oidc.DEFAULT_OIDC_ACCESS_TOKEN_PATH)

	fmt.Printf("CLI X.509 Certificate Validity: %s seconds\n", signer.DEFAULT_CRYPKI_VALIDITY)
	fmt.Printf("CLI X.509 Certificate Identifier: %s\n", signer.DEFAULT_CRYPKI_IDENTIFIER)
	fmt.Printf("CLI X.509 Certificate Request Timeout: %s seconds\n", signer.DEFAULT_CRYPKI_TIMEOUT)
}
