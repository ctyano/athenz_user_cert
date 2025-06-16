package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// Execute subcommand
	if len(os.Args) == 1 || strings.HasSuffix(os.Args[1], "help") {
		usage := `Usage:
  version:
    	print version
  generate:
    	generate private key and print the corresponding public key
  csr:
    	generate and print certificate signing request from the private key
`
		fmt.Printf(usage)
		flag.PrintDefaults()
		return
	}
	switch os.Args[1] {
	case "version":
		versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
		ExecuteVersionCommand(os.Args[2:], versionFlagSet)
	case "generate":
		generateFlagSet := flag.NewFlagSet("generate", flag.ExitOnError)
		ExecuteGenerateCommand(os.Args[2:], generateFlagSet)
	case "csr":
		csrFlagSet := flag.NewFlagSet("csr", flag.ExitOnError)
		ExecuteCsrCommand(os.Args[2:], csrFlagSet)
	default:
		log.Fatalf("%q is not valid command.", os.Args[1])
		return
	}
}
