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
	DEFAULT_SIGNER_CFSSL_URL     = "http://localhost:10000/api/v1/cfssl/sign"
	DEFAULT_SIGNER_CFSSL_TIMEOUT = "10" // in seconds
)

// https://github.com/cloudflare/cfssl/blob/master/doc/api/endpoint_sign.txt
func SendCFSSLCSR(url string, csr string, headers *map[string][]string) (error, string) {

	type RequestBody struct {
		CSR string `json:"certificate_request"`
		//Host           string `json:hosts`
		//SerialSequence string `json:"serial_sequence"`
		//Label          string `json:"label"`
		//Profile        string `json:"profile"`
		//Bundle         string `json:"bundle"`
	}

	body := RequestBody{
		CSR: csr,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %v", err), ""
	}

	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_SIGNER_CFSSL_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err), ""
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
		return fmt.Errorf("Failed to send request: %w", err), ""
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body) // safe to ignore error for error messages
		return fmt.Errorf("Received non-OK response: %s, body: %s", resp.Status, strings.TrimSpace(string(body))), ""
	}

	var response struct {
		Result struct {
			Certificate string `json:"certificate"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %w", err), ""
	}

	return nil, response.Result.Certificate
}
