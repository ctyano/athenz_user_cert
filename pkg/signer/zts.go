package signer

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ctyano/athenz_user_cert/pkg/certificate"
)

var (
	DEFAULT_SIGNER_ZTS_SIGN_URL = "https://127.0.0.1:4443/zts/v1/usercert"
	DEFAULT_SIGNER_ZTS_CA_URL   = certificate.CACertPath()
	DEFAULT_SIGNER_ZTS_TIMEOUT  = "10" // in seconds
)

func getZTSLocalPath(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}

	parsedURL, err := url.Parse(source)
	if err == nil {
		switch parsedURL.Scheme {
		case "http", "https":
			return ""
		case "file":
			return parsedURL.Path
		}
	}

	return source
}

func readZTSRootCA(source string) (string, error) {
	localPath := getZTSLocalPath(source)
	if localPath == "" {
		return "", nil
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("Failed to read CA certificate from %s: %w", localPath, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil
	}
	return string(data), nil
}

func newZTSHTTPClient(trustSource string) (*http.Client, error) {
	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_SIGNER_ZTS_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	caPEM, err := readZTSRootCA(trustSource)
	if err != nil {
		if !(errors.Is(err, os.ErrNotExist) && strings.TrimSpace(trustSource) == strings.TrimSpace(DEFAULT_SIGNER_ZTS_CA_URL)) {
			return nil, err
		}
	}
	if caPEM == "" && strings.TrimSpace(trustSource) != strings.TrimSpace(DEFAULT_SIGNER_ZTS_CA_URL) {
		caPEM, err = readZTSRootCA(DEFAULT_SIGNER_ZTS_CA_URL)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	if caPEM == "" {
		return client, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("Failed to parse CA certificate bundle")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	client.Transport = transport
	return client, nil
}

// SendZTSCSR sends a CSR to the Athenz ZTS user certificate endpoint.
func SendZTSCSR(name string, url string, csr string, attestationData string, trustSource string, headers *map[string][]string) (error, string) {
	type RequestBody struct {
		Name            string `json:"name"`
		CSR             string `json:"csr"`
		AttestationData string `json:"attestationData"`
	}

	body := RequestBody{
		Name:            name,
		CSR:             csr,
		AttestationData: attestationData,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %s", err), ""
	}

	client, err := newZTSHTTPClient(trustSource)
	if err != nil {
		return err, ""
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Failed to create request: %s", err), ""
	}

	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, values := range *headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
			return fmt.Errorf("Failed to send request: %s (set -ca-url to the Athenz CA PEM path if this is the first direct ZTS request)", err), ""
		}
		return fmt.Errorf("Failed to send request: %s", err), ""
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, url, strings.TrimSpace(string(body))), ""
	}

	var response struct {
		X509Certificate string `json:"x509Certificate"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.X509Certificate
}

// GetZTSRootCA returns the signer CA bundle from a local PEM file path or a remote endpoint.
func GetZTSRootCA(test bool, source string, headers *map[string][]string) (error, string) {
	caPEM, err := readZTSRootCA(source)
	if err == nil && caPEM != "" {
		return nil, caPEM
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && (test || strings.TrimSpace(source) == strings.TrimSpace(DEFAULT_SIGNER_ZTS_CA_URL)) {
			return nil, ""
		}
		return err, ""
	}

	if strings.TrimSpace(source) == "" {
		return nil, ""
	}

	client, err := newZTSHTTPClient(source)
	if err != nil {
		return err, ""
	}

	req, err := http.NewRequest("GET", source, bytes.NewBuffer(nil))
	if err != nil {
		return fmt.Errorf("Failed to create request: %s", err), ""
	}

	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, values := range *headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %s", err), ""
	}
	defer resp.Body.Close()

	if test && resp.StatusCode == http.StatusUnauthorized {
		return nil, ""
	}

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK status: %s, url: %s, response: %s", resp.Status, source, strings.TrimSpace(string(body))), ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read response body: %w", err), ""
	}

	caPEM, err = parseZTSRootCAResponse(body, source, test)
	if err != nil {
		return err, ""
	}

	return nil, caPEM
}

func parseZTSRootCAResponse(body []byte, source string, test bool) (string, error) {
	rawBody := strings.TrimSpace(string(body))
	if strings.HasPrefix(rawBody, "-----BEGIN CERTIFICATE-----") {
		return rawBody, nil
	}

	var response struct {
		X509CertificateSigner string `json:"x509CertificateSigner"`
		CACertBundle          string `json:"caCertBundle"`
		CACertificates        string `json:"caCertificates"`
		Certs                 string `json:"certs"`
		Certificate           string `json:"certificate"`
		Cert                  string `json:"cert"`
		Result                struct {
			Certificate string `json:"certificate"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		if test {
			return "", nil
		}
		return "", fmt.Errorf("Failed to parse JSON response: %w", err)
	}

	switch {
	case strings.TrimSpace(response.X509CertificateSigner) != "":
		return response.X509CertificateSigner, nil
	case strings.TrimSpace(response.CACertBundle) != "":
		return response.CACertBundle, nil
	case strings.TrimSpace(response.CACertificates) != "":
		return response.CACertificates, nil
	case strings.TrimSpace(response.Certs) != "":
		return response.Certs, nil
	case strings.TrimSpace(response.Certificate) != "":
		return response.Certificate, nil
	case strings.TrimSpace(response.Cert) != "":
		return response.Cert, nil
	case strings.TrimSpace(response.Result.Certificate) != "":
		return response.Result.Certificate, nil
	case test:
		return "", nil
	default:
		return "", fmt.Errorf("No CA certificate bundle found in response from %s", source)
	}
}
