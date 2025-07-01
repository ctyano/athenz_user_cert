package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	DEFAULT_X509_VALIDITY   = "30 * 24 * 60 * 60" // 30 days in seconds
	DEFAULT_X509_IDENTIFIER = "athenz"
	DEFAULT_X509_TIMEOUT    = "10" // in seconds
	DEFAULT_X509_ALGORITHM  = "RSA"
)

func SendCSR(url string, csr string, headers *map[string][]string) error {
	type KeyMeta struct {
		Identifier string `json:"identifier"`
	}

	type RequestBody struct {
		CSR      string  `json:"csr"`
		KeyMeta  KeyMeta `json:"key_meta"`
		Validity int     `json:"validity"`
	}

	validity, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_X509_VALIDITY))
	body := RequestBody{
		CSR: csr,
		KeyMeta: KeyMeta{
			Identifier: DEFAULT_X509_IDENTIFIER,
		},
		Validity: validity,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %v", err)
	}

	timeout, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_X509_TIMEOUT))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err)
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
		return fmt.Errorf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("Received non-OK response: %s", resp.Status)
	}

	var responseBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return fmt.Errorf("Failed to parse JSON response: %v", err)
	}

	fmt.Printf("%+v\n", responseBody["cert"])

	return nil
}
