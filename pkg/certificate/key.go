package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

var (
	DEFAULT_X509_USERKEY_PATH = "/.athenz/user.key.pem"
	DEFAULT_KEY_ALGORITHM     = "RSA"
)

// GenerateKey generates a private key for the specified algorithm.
// Supported algorithms are "RSA", "ECDSA", and "Ed25519".
func GenerateKey(algorithm string) (crypto.PrivateKey, error) {
	if algorithm == "" {
		algorithm = DEFAULT_KEY_ALGORITHM
	}
	switch algorithm {
	case "RSA":
		// Generate RSA key with 2048 bits
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ECDSA":
		// Generate ECDSA key using the P256 curve
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "Ed25519":
		// Generate Ed25519 key
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		return privateKey, err
	default:
		return nil, fmt.Errorf("unsupported algorithm:%s", algorithm)

	}
}

// PrivateKeyToPEM converts a crypto.PrivateKey to a PEM-encoded string (PKCS#8).
func PrivateKeyToPEM(priv crypto.PrivateKey) (*pem.Block, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}, nil
}

func PublicKeyFromPrivateKey(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch keytype := key.(type) {
	case *rsa.PrivateKey:
		return &keytype.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &keytype.PublicKey, nil
	case ed25519.PrivateKey:
		return keytype.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("Unsupported private key type. type:%T, struct:%#v, key:%#v", keytype, keytype, key)
	}
}

func Encrypt(pub crypto.PublicKey, data []byte) (err error, ciphertext string) {
	rsapub, ok := pub.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("Public key does not support encryption")
	}
	// Encryption
	rawciphertext, e := rsa.EncryptPKCS1v15(rand.Reader, rsapub, data)
	if e != nil {
		err = fmt.Errorf("Failed to encrypt: %v", e)
		return
	}
	// Base64 Url Encoding
	ciphertext = base64.URLEncoding.EncodeToString(rawciphertext)

	return
}

func Decrypt(priv crypto.PrivateKey, ciphertext string) (err error, data []byte) {
	rawciphertext, e := base64.URLEncoding.DecodeString(ciphertext)
	if e != nil {
		err = fmt.Errorf("Failed to decode string: %s", e)
		return
	}
	decryptor, ok := priv.(crypto.Decrypter)
	if !ok {
		err = fmt.Errorf("Private key does not support decryption")
	}
	data, err = decryptor.Decrypt(rand.Reader, rawciphertext, nil)
	if err != nil {
		err = fmt.Errorf("Failed to decrypt: %v", err)
	}

	return
}

func UserKeyPath() string {
	h, _ := os.UserHomeDir()
	return h + DEFAULT_X509_USERKEY_PATH
}
