package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var (
	DEFAULT_X509_VALIDITY   string
	DEFAULT_X509_IDENTIFIER string
	DEFAULT_X509_TIMEOUT    string
	DEFAULT_X509_ALGORITHM  string
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

	body := RequestBody{
		CSR: csr,
		KeyMeta: KeyMeta{
			Identifier: "athenz",
		},
		Validity: 30 * 24 * 60 * 60, // 30 days in seconds
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
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
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > http.StatusBadRequest {
		return fmt.Errorf("received non-OK response: %s", resp.Status)
	}

	var responseBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Printf("%+v\n", responseBody["cert"])

	return nil
}
