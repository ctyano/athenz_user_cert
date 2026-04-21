package oidc

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	DEFAULT_OIDC_CLIENT_ID             = "athenz-user-cert"
	DEFAULT_OIDC_CLIENT_SECRET         = "athenz-user-cert"
	DEFAULT_OIDC_ISSUER                = "http://127.0.0.1:5556/dex"
	DEFAULT_OIDC_SCOPES                = "openid email profile"
	DEFAULT_OIDC_LISTEN_ADDRESS        = ":8080"
	DEFAULT_OIDC_ACCESS_TOKEN_PATH     = ".athenz/.accesstoken"
	DEFAULT_OIDC_ACCESS_TOKEN_VALIDITY = "30" // in minutes
	DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM = "name"
)

type FileUtil interface {
	isCacheFileExpired(filename string, maxage float64) bool
	createCacheDir(dirname string) bool
	getCachedAccessToken() string
}

func getAccessTokenCachePath() string {
	h, _ := os.UserHomeDir()
	return h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
}

func getCachedAccessToken(debug bool) (string, error) {
	accessTokenFile := getAccessTokenCachePath()
	validity, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_OIDC_ACCESS_TOKEN_VALIDITY))
	if expired, err := isCacheFileExpired(accessTokenFile, float64(validity), debug); !expired && err == nil {
		data, err := os.ReadFile(accessTokenFile)
		if err != nil || expired {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	} else {
		return "", fmt.Errorf("could not check the cache file, error: %v", err)
	}
}

func isCacheFileExpired(filename string, maxAge float64, debug bool) (bool, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return false, fmt.Errorf("could not read the cache file, error: %v", err)
	}
	delta := time.Since(info.ModTime())
	// return false if duration exceeds maxAge
	if expired := delta.Minutes() > maxAge; expired {
		return expired, fmt.Errorf("access token has expired")
	}
	return false, nil
}

func createCacheDir(dirname string, debug bool) (bool, error) {
	if debug {
		fmt.Printf("Checking if directory %s exists...\n", dirname)
	}
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if debug {
			fmt.Printf("Failed to read the cache directory %s. Creating one.\n", dirname)
		}
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			return false, fmt.Errorf("failed to create directory: %v", err)
		}
	} else if err != nil {
		return false, fmt.Errorf("failed to check directory: %v", err)
	} else {
		if debug {
			fmt.Printf("the cache directory %s exists.\n", dirname)
		}
	}
	return true, nil
}

func GetOIDCDiscovery(debug *bool) (string, string, error) {
	discoveryURL := strings.TrimSuffix(DEFAULT_OIDC_ISSUER, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to discover OIDC config from %s: %v", DEFAULT_OIDC_ISSUER, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("failed to discover OIDC config from %s: %s: %s", DEFAULT_OIDC_ISSUER, resp.Status, strings.TrimSpace(string(body)))
	}

	var discovery struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", "", fmt.Errorf("failed to parse OIDC provider endpoints: %v", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return "", "", fmt.Errorf("OIDC discovery document from %s did not include authorization/token endpoints", DEFAULT_OIDC_ISSUER)
	}
	if *debug {
		fmt.Printf("Discovered authorization endpoint: %s\n", discovery.AuthorizationEndpoint)
		fmt.Printf("Discovered token endpoint: %s\n", discovery.TokenEndpoint)
	}

	return discovery.AuthorizationEndpoint, discovery.TokenEndpoint, nil
}

type authCodeResult struct {
	Code            string
	AttestationData string
}

type oauthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
}

func buildOAuthConfig(authURL, tokenURL string) *oauthConfig {
	return &oauthConfig{
		ClientID:     DEFAULT_OIDC_CLIENT_ID,
		ClientSecret: DEFAULT_OIDC_CLIENT_SECRET,
		RedirectURL:  "http://127.0.0.1" + DEFAULT_OIDC_LISTEN_ADDRESS,
		Scopes:       strings.Split(DEFAULT_OIDC_SCOPES, " "),
		AuthURL:      authURL,
		TokenURL:     tokenURL,
	}
}

func buildAuthCodeURL(conf *oauthConfig, responseMode string) (string, error) {
	authURL, err := url.Parse(conf.AuthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth URL: %v", err)
	}

	query := authURL.Query()
	query.Set("client_id", conf.ClientID)
	query.Set("redirect_uri", conf.RedirectURL)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(conf.Scopes, " "))
	query.Set("state", "state")
	query.Set("access_type", "offline")
	if responseMode != "" {
		query.Set("response_mode", responseMode)
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func exchangeAuthCode(conf *oauthConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", conf.RedirectURL)
	form.Set("client_id", conf.ClientID)
	if conf.ClientSecret != "" {
		form.Set("client_secret", conf.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, conf.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	accessToken := token.AccessToken
	if accessToken != "" {
		accessTokenFilePath := getAccessTokenCachePath()
		createCacheDir(filepath.Dir(accessTokenFilePath), false)
		err := os.WriteFile(accessTokenFilePath, []byte(accessToken), 0600)
		if err != nil {
			return "", fmt.Errorf("failed to store access token to: %s, error %s", accessTokenFilePath, err)
		}
	}
	return accessToken, nil
}

func parseAuthInput(raw string) (authCodeResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return authCodeResult{}, fmt.Errorf("authorization response is empty")
	}

	values, err := url.ParseQuery(raw)
	if err == nil && values.Get("code") != "" {
		return authCodeResult{
			Code:            values.Get("code"),
			AttestationData: raw,
		}, nil
	}

	return authCodeResult{
		Code:            raw,
		AttestationData: raw,
	}, nil
}

func getAuthCodeResult(conf *oauthConfig, responseMode *string) (authCodeResult, error) {
	if runtime.GOOS == "darwin" {
		serverDone := make(chan authCodeResult, 1)
		go func() {
			serverDone <- waitForCodeServer(DEFAULT_OIDC_LISTEN_ADDRESS)
		}()
		authCodeURL, err := buildAuthCodeURL(conf, *responseMode)
		if err != nil {
			return authCodeResult{}, err
		}
		fmt.Printf("Your browser should open. If not, open this URL:\n%s\n\n", authCodeURL)
		_ = exec.Command("open", authCodeURL).Start()
		result := <-serverDone
		if result.Code == "" {
			return authCodeResult{}, fmt.Errorf("no authorization code in callback")
		}
		return result, nil
	}

	manualConf := *conf
	manualConf.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
	authCodeURL, err := buildAuthCodeURL(&manualConf, *responseMode)
	if err != nil {
		return authCodeResult{}, err
	}
	fmt.Printf("Open the following URL in your browser, log in, then paste the resulting authorization response here:\n%s\n", authCodeURL)
	if *responseMode == "form_post" {
		fmt.Printf("\nPaste the full callback payload (for example: code=...&state=...), or just the code value.\n")
	}
	fmt.Print("Enter the authorization response: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return parseAuthInput(scanner.Text())
	}
	return authCodeResult{}, fmt.Errorf("failed to read authorization response")
}

func GetAuthAttestationDataAndAccessToken(responseMode *string, debug *bool) (string, string, error) {
	authURL, tokenURL, err := GetOIDCDiscovery(debug)
	if err != nil {
		return "", "", err
	}

	conf := buildOAuthConfig(authURL, tokenURL)
	authResult, err := getAuthCodeResult(conf, responseMode)
	if err != nil {
		return "", "", err
	}

	accessToken, err := exchangeAuthCode(conf, authResult.Code)
	if err != nil {
		return "", "", err
	}

	return authResult.AttestationData, accessToken, nil
}

func GetAuthAccessToken(responseMode *string, debug *bool) (string, error) {
	accessToken, err := getCachedAccessToken(*debug)
	if *debug && err != nil {
		fmt.Printf("Failed get cached access token: %s\n", err)
	}
	if accessToken != "" {
		return accessToken, err
	}

	authURL, tokenURL, err := GetOIDCDiscovery(debug)
	if err != nil {
		return "", err
	}

	conf := buildOAuthConfig(authURL, tokenURL)
	authResult, err := getAuthCodeResult(conf, responseMode)
	if err != nil {
		return "", err
	}

	return exchangeAuthCode(conf, authResult.Code)
}

// waitForCodeServer runs a local HTTP server to capture the OAuth2 code via GET or POST.
// Returns the code and the raw callback payload.
func waitForCodeServer(listenAddress string) authCodeResult {
	codeCh := make(chan authCodeResult)
	mux := http.NewServeMux()
	server := &http.Server{Addr: listenAddress, Handler: mux}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var code, attestationData string
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}
			code = r.FormValue("code")
			attestationData = r.PostForm.Encode()
		} else {
			code = r.URL.Query().Get("code")
			attestationData = r.URL.RawQuery
		}
		if code == "" {
			http.Error(w, "No code in request", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Login successful! You can close this tab.")
		codeCh <- authCodeResult{
			Code:            code,
			AttestationData: attestationData,
		}
	})

	go func() {
		_ = server.ListenAndServe()
	}()
	defer func() { time.Sleep(1 * time.Second); server.Close() }()

	return <-codeCh
}

func GetUserNameFromAccessToken(rawJWT, userNameClaim string) (string, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid jwt: %s", rawJWT)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %s, error: %s", rawJWT, err)
	}

	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("invalid jwt payload: %s", err)
	}

	var userClaim string
	if userNameClaim != "" {
		userClaim = userNameClaim
	} else {
		userClaim = DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM
	}
	name, ok := claims[userClaim].(string)
	if !ok {
		return "", fmt.Errorf("no %s claim in jwt", userClaim)
	}
	return name, nil
}
