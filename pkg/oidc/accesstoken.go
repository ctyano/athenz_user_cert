package oidc

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var (
	DEFAULT_OIDC_CLIENT_ID             = "athenz-user-cert"
	DEFAULT_OIDC_CLIENT_SECRET         = "athenz-user-cert"
	DEFAULT_OIDC_ISSUER                = "http://localhost:5556/dex"
	DEFAULT_OIDC_SCOPES                = "openid email profile"
	DEFAULT_OIDC_LISTEN_ADDRESS        = ":8080"
	DEFAULT_OIDC_ACCESS_TOKEN_PATH     = ".athenz/.accesstoken"
	DEFAULT_OIDC_ACCESS_TOKEN_VALIDITY = "30" // in minutes
	debug                              = true
)

type FileUtil interface {
	isCacheFileFresh(filename string, maxage float64) bool
	createCacheDir(dirname string) bool
	getCachedAccessToken() string
}

func getAccessTokenCachePath() string {
	h, _ := os.UserHomeDir()
	return h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
}

func getCachedAccessToken() string {
	h, _ := os.UserHomeDir()
	accessTokenFile := h + "/.athenz/.accesstoken"
	validity, _ := strconv.Atoi(strings.TrimSpace(DEFAULT_OIDC_ACCESS_TOKEN_VALIDITY))
	if isCacheFileFresh(accessTokenFile, float64(validity)) {
		data, err := ioutil.ReadFile(accessTokenFile)
		if err != nil {
			fmt.Printf("Could not read the file, error: %v\n", err)
		}
		return strings.TrimSpace(string(data))
	}
	return ""
}

func isCacheFileFresh(filename string, maxAge float64) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if debug {
			fmt.Printf("Could not read the cache file, error: %v\n", err)
		}
		return false
	}
	delta := time.Since(info.ModTime())
	// return false if duration exceeds maxAge
	expired := delta.Minutes() > maxAge
	return !expired
}

func createCacheDir(dirname string) bool {
	if debug {
		fmt.Printf("Checking if directory %s exists...\n", dirname)
	}
	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		if debug {
			fmt.Printf("Failed to read the cache directory %s. Creating one.\n", dirname)
		}
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			fmt.Printf("Failed to create directory: %v", err)
			return false
		}
	} else if err != nil {
		fmt.Printf("Failed to check directory: %v", err)
		return false
	} else {
		if debug {
			fmt.Printf("The cache directory %s exists.\n", dirname)
		}
	}
	return true
}

func GetAuthAccessToken() (string, error) {
	accessToken := getCachedAccessToken()
	if accessToken != "" {
		return accessToken, nil
	}

	// ==== FLAGS ====
	var responseMode string
	flag.StringVar(&responseMode, "response-mode", "query", "OAuth2 response_mode (query or form_post)")
	flag.Parse()

	// ==== CONFIG ====
	issuer := "http://127.0.0.1:5556/dex" // change as needed
	clientID := "athenz-user-cert"
	clientSecret := "athenz-user-cert"
	redirectURL := "http://localhost:8080/callback"
	scopes := []string{"openid", "email", "profile"}

	authURL := issuer + "/auth"
	tokenURL := issuer + "/token"

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	// ==== START LOCAL SERVER TO CATCH REDIRECT ====
	codeCh := make(chan string)
	u, _ := url.Parse(redirectURL)
	if !strings.Contains(u.Host, ":") {
		return "", fmt.Errorf("Invalid redirect URL: " + redirectURL)
	}
	parts := strings.Split(u.Host, ":")
	srv := &http.Server{Addr: ":" + parts[len(parts)-1]}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		var code string
		if r.Method == "POST" {
			// response_mode=form_post: parse form
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form", http.StatusBadRequest)
				return
			}
			code = r.FormValue("code")
		} else {
			// response_mode=query: parse URL
			code = r.URL.Query().Get("code")
		}
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Login successful! You can close this tab.")
		codeCh <- code
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("ListenAndServe: %v", err)
		}
	}()
	defer srv.Close()

	// ==== OPEN BROWSER FOR USER AUTH ====
	authCodeURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	// Append response_mode param manually, since x/oauth2 does not set it
	authCodeURL += "&response_mode=" + responseMode

	fmt.Printf("Open this URL in your browser if it does not open automatically:\n%s\n", authCodeURL)
	openBrowser(authCodeURL)

	// ==== WAIT FOR AUTH CODE ====
	code := <-codeCh

	// ==== EXCHANGE CODE FOR TOKEN ====
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}
	accessToken = token.AccessToken
	fmt.Printf("Access token: %s\n", accessToken)

	if accessToken != "" {
		h, _ := os.UserHomeDir()
		accessTokenFilePath := h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
		createCacheDir(filepath.Dir(accessTokenFilePath))
		ioutil.WriteFile(accessTokenFilePath, []byte(accessToken), 0600)
	}
	return accessToken, nil
}

// openBrowser tries to open the URL in the default browser on any OS
func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", etc.
		cmd = "xdg-open"
		args = []string{url}
	}

	// Run the command in the background, ignore errors
	_ = exec.Command(cmd, args...).Start()
}
