package certificate

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type X509Options struct {
	CommonName string
	San        string
	ValidFrom  string
	ValidFor   time.Duration
	IsCA       bool
	KeyUsage   x509.KeyUsage
}

func keyUsageFromAlgorithm(alg x509.PublicKeyAlgorithm) (err error, keyUsage x509.KeyUsage) {
	switch alg {
	case x509.RSA:
		// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
		// the context of TLS this KeyUsage is particular to RSA key exchange and
		// authentication.
		keyUsage |= x509.KeyUsageKeyEncipherment
	case x509.ECDSA:
		// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
		// KeyUsage bits set in the x509.Certificate template
		keyUsage |= x509.KeyUsageDigitalSignature
	case x509.Ed25519:
		// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
		// KeyUsage bits set in the x509.Certificate template
		keyUsage |= x509.KeyUsageDigitalSignature
	case x509.DSA:
		// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
		// KeyUsage bits set in the x509.Certificate template
		keyUsage |= x509.KeyUsageDigitalSignature
	case x509.UnknownPublicKeyAlgorithm:
		err = fmt.Errorf("Unknown Public Key Algorithm. Type: %s", alg)
	default:
		err = fmt.Errorf("Unsupported Public Key Algorithm. Type: %s", alg)
	}

	return
}

func ReadCSR(csrPath string) (err error, csr *x509.CertificateRequest) {
	data, err := ioutil.ReadFile(csrPath)
	if err != nil {
		err = fmt.Errorf("Failed to read csr file: %v", err)
		return
	}

	b, _ := pem.Decode(data)
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}

	return
}

func ParseCSRToX509Options(csr *x509.CertificateRequest, opt **X509Options) (err error, csrPublicKey crypto.PublicKey) {
	(*opt).CommonName = csr.Subject.CommonName
	var sans []string
	if len(csr.DNSNames) != 0 {
		sans = append(sans, csr.DNSNames...)
	}
	if len(csr.EmailAddresses) != 0 {
		sans = append(sans, csr.EmailAddresses...)
	}
	for _, v := range csr.IPAddresses {
		sans = append(sans, v.String())
	}
	for _, v := range csr.URIs {
		sans = append(sans, v.String())
	}
	(*opt).San = strings.Join(sans, ",")

	err, (*opt).KeyUsage = keyUsageFromAlgorithm(csr.PublicKeyAlgorithm)
	csrPublicKey = csr.PublicKey

	return
}

func GenerateX509Template(opt *X509Options, priv crypto.PrivateKey, cacert *x509.Certificate) (err error, cert *x509.Certificate) {
	var notBefore time.Time
	if len((*opt).ValidFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006 JST", (*opt).ValidFrom)
		if err != nil {
			err = fmt.Errorf("Failed to parse creation date: %v", err)
			return
		}
	}

	notAfter := notBefore.Add((*opt).ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = fmt.Errorf("Failed to generate serial number: %v", err)
		return
	}

	if err != nil {
		err = fmt.Errorf("Failed to get X.509 Key Usage: %v", err)
		return
	}

	var subject pkix.Name
	if cacert != nil {
		subject = pkix.Name{
			Country:            cacert.Subject.Country,
			Organization:       cacert.Subject.Organization,
			OrganizationalUnit: cacert.Subject.OrganizationalUnit,
			Locality:           cacert.Subject.Locality,
			Province:           cacert.Subject.Province,
			StreetAddress:      cacert.Subject.StreetAddress,
			PostalCode:         cacert.Subject.PostalCode,
			SerialNumber:       cacert.Subject.SerialNumber,
		}
	}
	subject.CommonName = (*opt).CommonName
	cert = &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage: (*opt).KeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	if len((*opt).San) != 0 {
		sans := strings.Split((*opt).San, ",")
		for _, host := range sans {
			if ip := net.ParseIP(host); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, host)
			}
		}
	}

	if (*opt).IsCA {
		cert.IsCA = (*opt).IsCA
		cert.KeyUsage |= x509.KeyUsageCertSign
		cert.ExtKeyUsage = nil
	}

	return
}

func VerifyCertificate(cert, cacert *x509.Certificate) (err error) {
	roots := x509.NewCertPool()
	roots.AddCert(cacert)

	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	if err != nil {
		err = fmt.Errorf("Failed to verify certificate: %v", err)
		return
	}

	return
}

func WritePem(certPem *pem.Block, certPath string) (err error) {
	certOut, err := os.Create(certPath)
	if err != nil {
		err = fmt.Errorf("Failed to open %s for writing: %v", certPath, err)
		return
	}
	err = pem.Encode(certOut, certPem)
	if err != nil {
		err = fmt.Errorf("Failed to write data to cert.pem: %v", err)
		return
	}
	err = certOut.Close()
	if err != nil {
		err = fmt.Errorf("Error closing %s: %v", certPath, err)
		return
	}

	return
}
