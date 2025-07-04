package oidc

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
	DEFAULT_OIDC_ISSUER                = "http://127.0.0.1:5556/dex"
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
	accessTokenFile := h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
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
	authURL := DEFAULT_OIDC_ISSUER + "/auth"
	tokenURL := DEFAULT_OIDC_ISSUER + "/token"

	conf := &oauth2.Config{
		ClientID:     DEFAULT_OIDC_CLIENT_ID,
		ClientSecret: DEFAULT_OIDC_CLIENT_SECRET,
		RedirectURL:  "http://127.0.0.1" + DEFAULT_OIDC_LISTEN_ADDRESS,
		Scopes:       strings.Split(DEFAULT_OIDC_SCOPES, " "),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	// ==== OS logic ====
	code := ""
	var serverDone chan struct{}
	if runtime.GOOS == "darwin" {
		// On macOS: open browser, run HTTP server, get code automatically
		serverDone = make(chan struct{})
		go func() {
			code = waitForCodeServer(DEFAULT_OIDC_LISTEN_ADDRESS, responseMode)
			close(serverDone)
		}()
		authCodeURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		authCodeURL += "&response_mode=" + responseMode
		fmt.Printf("Your browser should open. If not, open this URL:\n%s\n", authCodeURL)
		_ = exec.Command("open", authCodeURL).Start()
		<-serverDone
	} else {
		// On Windows/Linux: print URL, user logs in, then copy-pastes code
		conf.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
		authCodeURL := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		authCodeURL += "&response_mode=" + responseMode
		fmt.Printf("Open the following URL in your browser, log in, then paste the resulting code here:\n%s\n", authCodeURL)
		if responseMode == "form_post" {
			fmt.Println("\nAfter login, you will see a blank or success page. Copy the 'code' value from the form POST (using browser dev tools or see the redirected form), and paste it below.")
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
	defer server.Close()

	code := <-codeCh
	return code
}
