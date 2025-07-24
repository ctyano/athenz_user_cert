package oidc

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
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
		data, err := ioutil.ReadFile(accessTokenFile)
		if err != nil {
			return "", fmt.Errorf("Could not read the cache file, error: %v\n", err)
		}
		if expired {
			return "", fmt.Errorf("Access Token has expired.\n")
		}
		return strings.TrimSpace(string(data)), nil
	} else {
		return "", fmt.Errorf("Could not check the cache file, error: %v\n", err)
	}
}

func isCacheFileExpired(filename string, maxAge float64, debug bool) (bool, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return false, fmt.Errorf("Could not read the cache file, error: %v\n", err)
	}
	delta := time.Since(info.ModTime())
	// return false if duration exceeds maxAge
	expired := delta.Minutes() > maxAge
	return expired, nil
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
			return false, fmt.Errorf("Failed to create directory: %v", err)
		}
	} else if err != nil {
		return false, fmt.Errorf("Failed to check directory: %v", err)
	} else {
		if debug {
			fmt.Printf("The cache directory %s exists.\n", dirname)
		}
	}
	return true, nil
}

func GetAuthAccessToken(responseMode *string, debug *bool) (string, error) {
	accessToken, err := getCachedAccessToken(*debug)
	if *debug && err != nil {
		fmt.Printf("Failed get cached access token: %s", err)
	}
	if accessToken != "" {
		return accessToken, err
	}

	// ==== OIDC Discovery ====
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, DEFAULT_OIDC_ISSUER)
	if err != nil {
		return "", fmt.Errorf("Failed to discover OIDC config from %s: %v", DEFAULT_OIDC_ISSUER, err)
	}
	endpoints := provider.Endpoint()
	if err != nil {
		return "", fmt.Errorf("Failed to parse OIDC provider endpoints: %v", err)
	}
	if *debug {
		fmt.Printf("Discovered authorization endpoint: %s\n", endpoints.AuthURL)
		fmt.Printf("Discovered token endpoint: %s\n", endpoints.TokenURL)
	}

	// ==== CONFIG ====
	conf := &oauth2.Config{
		ClientID:     DEFAULT_OIDC_CLIENT_ID,
		ClientSecret: DEFAULT_OIDC_CLIENT_SECRET,
		RedirectURL:  "http://127.0.0.1" + DEFAULT_OIDC_LISTEN_ADDRESS,
		Scopes:       strings.Split(DEFAULT_OIDC_SCOPES, " "),
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpoints.AuthURL,
			TokenURL: endpoints.TokenURL,
		},
	}

	// ==== OS logic ====
	code := ""
	var serverDone chan struct{}
	if runtime.GOOS == "darwin" {
		// On macOS: open browser, run HTTP server, get code automatically
		serverDone = make(chan struct{})
		go func() {
			code = waitForCodeServer(DEFAULT_OIDC_LISTEN_ADDRESS, *responseMode)
			close(serverDone)
		}()
		authCodeURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		authCodeURL += "&response_mode=" + *responseMode
		fmt.Printf("Your browser should open. If not, open this URL:\n%s\n\n", authCodeURL)
		_ = exec.Command("open", authCodeURL).Start()
		<-serverDone
	} else {
		// On Windows/Linux: print URL, user logs in, then copy-pastes code
		conf.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
		authCodeURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		authCodeURL += "&response_mode=" + *responseMode
		fmt.Printf("Open the following URL in your browser, log in, then paste the resulting code here:\n%s\n", authCodeURL)
		if *responseMode == "form_post" {
			fmt.Printf("\nAfter login, you will see a blank or success page. ")
			fmt.Printf("Copy the 'code' value from the form POST (using browser dev tools or see the redirected form), and paste it below.\n")
		}
		fmt.Print("Enter the authorization code: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			code = strings.TrimSpace(scanner.Text())
		}
	}

	// ==== EXCHANGE CODE FOR TOKEN ====
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("Token exchange failed: %v", err)
	}

	accessToken = token.AccessToken

	if accessToken != "" {
		accessTokenFilePath := getAccessTokenCachePath()
		createCacheDir(filepath.Dir(accessTokenFilePath), *debug)
		err := ioutil.WriteFile(accessTokenFilePath, []byte(accessToken), 0600)
		if err != nil {
			return "", fmt.Errorf("Failed to store access token to: %s, error %s", accessTokenFilePath, err)
		}
	}
	return accessToken, nil
}

// waitForCodeServer runs a local HTTP server to capture the OAuth2 code via GET or POST.
// Returns the code string.
func waitForCodeServer(listenAddress, responseMode string) string {
	codeCh := make(chan string)
	server := &http.Server{Addr: listenAddress}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var code string
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}
			code = r.FormValue("code")
		} else {
			code = r.URL.Query().Get("code")
		}
		if code == "" {
			http.Error(w, "No code in request", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Login successful! You can close this tab.")
		codeCh <- code
	})

	go func() {
		_ = server.ListenAndServe()
	}()
	defer func() { time.Sleep(1 * time.Second); server.Close() }()

	code := <-codeCh
	return code
}

func GetUserNameFromAccessToken(rawJWT, userNameClaim string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(rawJWT, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("Invalid JWT: %s, error: %s", rawJWT, err)
	}
	claims := token.Claims.(jwt.MapClaims)
	var userClaim string
	if userNameClaim != "" {
		userClaim = userNameClaim
	} else {
		userClaim = DEFAULT_OIDC_ATHENZ_USERNAME_CLAIM
	}
	name, ok := claims[userClaim].(string)
	if !ok {
		return "", fmt.Errorf("No %s claim in JWT", userClaim)
	}
	return name, nil
}
