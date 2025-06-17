package main

import (
	"flag"
)

func ExecuteAuthenticateCommand(arg []string, authenticateFlagSet *flag.FlagSet) {

	authenticateFlagSet.Parse(arg)

}
