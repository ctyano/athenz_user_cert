package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	"github.com/ctyano/athenz-user-cert/pkg/certificate"
)

func ExecuteGenerateCommand(arg []string, generateFlagSet *flag.FlagSet) {

	generateFlagSet.Parse(arg)

	publicKey, err := certificate.GenerateKey("RSA")
	if err != nil {
		log.Fatalf("failed to generate a key: %s", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("failed to marshal public key: %w", err)
	}

	keyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	fmt.Printf("%s", pem.EncodeToMemory(keyPEM))
}
