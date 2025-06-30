package oidc

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/smallstep/cli/command"
	_ "github.com/smallstep/cli/command/oauth"
	"github.com/smallstep/cli/config"
	"github.com/urfave/cli"
)

var (
	DEFAULT_OIDC_CLIENT_ID         string
	DEFAULT_OIDC_CLIENT_SECRET     string
	DEFAULT_OIDC_ISSUER            string // e.g., http://localhost:5556/dex
	DEFAULT_OIDC_SCOPES            string // e.g. openid email profile
	DEFAULT_OIDC_LISTEN_ADDRESS    string // e.g. :8080, or localhost:4080
	DEFAULT_OIDC_ACCESS_TOKEN_PATH string // under the home directory e.g. .athenz/.accesstoken
	//DEFAULT_OIDC_CALLBACK          string // e.g., http://localhost:8080/callback
)

type FileUtil interface {
	isFreshFile(filename string, maxage float64) bool
	getCachedAccessToken() string
}

type FileIo struct {
	FileUtil
	ioutilReadFile func(string) ([]byte, error)
	osGetenv       func(string) string
	osStat         func(string) (fs.FileInfo, error)
	debug          bool
}

func getAccessTokenCachePath() string {
	h, _ := os.UserHomeDir()
	return h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
}

func (fio *FileIo) isFreshFile(filename string, maxAge float64) bool {
	info, err := fio.osStat(filename)
	if err != nil {
		if fio.debug {
			fmt.Printf("Couldn't read the cache file, error: %v\n", err)
		}
		return false
	}
	delta := time.Since(info.ModTime())
	// return false if duration exceeds maxAge
	expired := delta.Minutes() > maxAge
	return !expired
}

func (fio *FileIo) getCachedAccessToken() string {
	h, _ := os.UserHomeDir()
	accessTokenFile := h + "/.athenz/.accesstoken"
	if fio.isFreshFile(accessTokenFile, 30) {
		data, err := fio.ioutilReadFile(accessTokenFile)
		if err != nil {
			fmt.Printf("Couldn't read the file, error: %v\n", err)
		}
		return strings.TrimSpace(string(data))
	}
	return ""
}

type AccessToken struct {
	fu              FileUtil
	ioutilWriteFile func(filename string, data []byte, perm fs.FileMode) error
	app             *cli.App
	Run             func(args []string) error
	debug           bool
}

func NewAccessToken(debug bool) *AccessToken {
	app := cli.NewApp()
	at := &AccessToken{
		fu: &FileIo{
			osGetenv:       os.Getenv,
			osStat:         os.Stat,
			ioutilReadFile: ioutil.ReadFile,
			debug:          debug,
		},
		app:             app,
		Run:             app.Run,
		ioutilWriteFile: ioutil.WriteFile,
		debug:           debug,
	}
	return at
}

func (at *AccessToken) GetAuthAccessToken() (string, error) {

	accessToken := at.fu.getCachedAccessToken()
	if accessToken != "" {
		return accessToken, nil
	}

	args := []string{
		"step",
		"oauth",
		"--bare",
		"--scope=" + DEFAULT_OIDC_SCOPES,
		"--provider=" + DEFAULT_OIDC_ISSUER,
		"--client-id=" + DEFAULT_OIDC_CLIENT_ID,
		"--client-secret=" + DEFAULT_OIDC_CLIENT_SECRET,
		"--listen=" + DEFAULT_OIDC_LISTEN_ADDRESS,
		//"--redirect-url=" + DEFAULT_OIDC_CALLBACK,
		//"--console",
	}

	fmt.Println("args: " + strings.Join(args, " "))

	// https://github.com/smallstep/cli/blob/6a18ddaf61684ca14369ed962aadeccfc6e59665/internal/cmd/root.go
	// step oauth --authorization-endpoint=https://oauth2.athenz.svc.cluster.local:5556/dex/auth --token-endpoint=https://oauth2.athenz.svc.cluster.local:5556/dex/token --client-id=athenz-user-cert --client-secret=athenz-user-cert --scope="openid profile email" --listen-url http://localhost:8080/callback --listen :8080
	at.app.Name = "step"
	at.app.HelpName = "step"
	at.app.Usage = "plumbing for distributed systems"
	at.app.Version = config.Version()
	at.app.Commands = command.Retrieve()
	at.app.Flags = append(at.app.Flags, cli.HelpFlag)
	at.app.EnableBashCompletion = true
	at.app.Copyright = "https://github.com/ctyano"

	at.app.Flags = append(at.app.Flags, cli.StringFlag{
		Name:  "config",
		Usage: "path to the config file to use for CLI flags",
	})

	at.app.Writer = os.Stdout
	at.app.ErrWriter = os.Stderr

	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	oldSto := os.Stdout
	os.Stdout = w

	if err := at.Run(args); err != nil {
		fmt.Println(err)
		return "", err
	}

	os.Stdout = oldSto
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	accesstoken := strings.TrimRight(buf.String(), "\n")

	if accesstoken != "" {
		h, _ := os.UserHomeDir()
		accessTokenFile := h + "/" + DEFAULT_OIDC_ACCESS_TOKEN_PATH
		data := []byte(accesstoken)
		at.ioutilWriteFile(accessTokenFile, data, 0600)
	}
	return accesstoken, nil
}
