package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	DEFAULT_CFSSL_TIMEOUT = "10" // in seconds
)

// https://github.com/cloudflare/cfssl/blob/master/doc/api/endpoint_sign.txt
func SendCFSSLCSR(url string, csr string, headers *map[string][]string) (error, *string) {

	type RequestBody struct {
		CSR            string `json:"certificate_request"`
		Host           string `json:hosts`
		SerialSequence string `json:"serial_sequence"`
		Label          string `json:"label"`
		Profile        string `json:"profile"`
		Bundle         string `json:"bundle"`
	}

	body := RequestBody{
		CSR: csr,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %v", err), nil
	}

	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_CFSSL_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err), nil
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
		return fmt.Errorf("Failed to send request: %v", err), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Received non-OK response: %s, error: %s", resp.Status, body), nil
	}

	var responseBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %s", err), nil
	}
	cert := fmt.Sprintf("%s", responseBody["certificate"])
	fmt.Printf("%s\n", cert)

	return nil, &cert
}
