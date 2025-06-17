package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	appname := os.Args[0]
	if len(os.Args) == 2 {
		usage := fmt.Sprintf(`Usage of %s:
  Generate certificate signing request and send the csr to the server.

  Subcommands:
    version:
    	Print the version of this CLI.
    generate:
    	Generate private key and print the corresponding public key.
`, appname)
		switch {
		case "version" == os.Args[1]:
			versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
			ExecuteVersionCommand(os.Args[2:], versionFlagSet)
		case "generate" == os.Args[1]:
			generateFlagSet := flag.NewFlagSet("generate", flag.ExitOnError)
			ExecuteGenerateCommand(os.Args[2:], generateFlagSet)
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
