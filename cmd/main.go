package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	DEFAULT_APP_NAME = "athenz-user-cert"
)

func main() {
	appname := DEFAULT_APP_NAME

	if len(os.Args) == 2 {
		usage := fmt.Sprintf(`Usage of %s:
  Generate certificate signing request and send the csr to the server.

  Subcommands:
    version:
    	Print the version and the pre desined parameters of this CLI.
    authenticate:
    	Authenticate user with Open ID Connect protocol and retrieve OAuth Access Token.
`, appname)
		switch {
		case "version" == os.Args[1]:
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(os.Args[2:], versionFlagSet)
		case "authenticate" == os.Args[1]:
			authenticateFlagSet := flag.NewFlagSet("authenticate", flag.ExitOnError)
			ExecuteAuthenticateCommand(os.Args[2:], authenticateFlagSet)
		case strings.HasSuffix(os.Args[1], "help"):
			fmt.Printf(usage)
			flag.PrintDefaults()
		default:
			csrFlagSet := flag.NewFlagSet("", flag.ExitOnError)
			ExecuteCsrCommand(os.Args[1:], csrFlagSet)
		}
	} else {
		csrFlagSet := flag.NewFlagSet("", flag.ExitOnError)
		ExecuteCsrCommand(os.Args[1:], csrFlagSet)
	}
}
