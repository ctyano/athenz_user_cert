package main

import (
	"flag"
	"fmt"
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
}
