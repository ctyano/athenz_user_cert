ifeq ($(APP_NAME),)
APP_NAME := $(shell basename $(shell pwd))
endif

ifeq ($(APP_REPO_OWNER),)
APP_REPO_OWNER := ctyano
endif
ifeq ($(APP_REPO_DOMAIN),)
APP_REPO_DOMAIN := github.com
endif
ifeq ($(APP_REPO_URL),)
APP_REPO_URL := $(APP_REPO_DOMAIN)/$(APP_REPO_OWNER)/$(APP_NAME)
endif

LDFLAGS :=
ifneq ($(VERSION),)
LDFLAGS_ARGS += -X 'main.VERSION=$(VERSION)'
else
LDFLAGS_ARGS += -X 'main.VERSION=$(shell git rev-parse --short HEAD)'
endif
ifneq ($(BUILD_DATE),)
LDFLAGS_ARGS += -X 'main.BUILD_DATE=$(BUILD_DATE)'
else
LDFLAGS_ARGS += -X 'main.BUILD_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S%Z%z')'
endif
ifneq ($(DEFAULT_OIDC_CLIENT_ID),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_ID=$(DEFAULT_OIDC_CLIENT_ID)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_ID=athenz-user-cert'
endif
ifneq ($(DEFAULT_OIDC_CLIENT_SECRET),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_SECRET=$(DEFAULT_OIDC_CLIENT_SECRET)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CLIENT_SECRET=athenz-user-cert'
endif
ifneq ($(DEFAULT_OIDC_ISSUER),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ISSUER=$(DEFAULT_OIDC_ISSUER)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_ISSUER=https://oauth2.athenz.svc.cluster.local:5556/dex'
endif
ifneq ($(DEFAULT_OIDC_CALLBACK),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CALLBACK=$(DEFAULT_OIDC_CALLBACK)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_CALLBACK=http://localhost:8080/callback'
endif
ifneq ($(DEFAULT_OIDC_LISTEN_ADDRESS),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_LISTEN_ADDRESS=$(DEFAULT_OIDC_LISTEN_ADDRESS)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_LISTEN_ADDRESS=":8080"'
endif
ifneq ($(DEFAULT_OIDC_SCOPES),)
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_SCOPES=$(DEFAULT_OIDC_SCOPES)'
else
LDFLAGS_ARGS += -X '$(APP_REPO_URL)/pkg/oidc.DEFAULT_OIDC_SCOPES="openid\ email\ profile"'
endif

ifneq ($(LDFLAGS_ARGS),)
LDFLAGS += -ldflags "$(LDFLAGS_ARGS)"
endif

.PHONY: submodule-update build test clean

build: submodule-update
	@echo "Building $(APP_NAME)..."
	go mod tidy
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(GOPATH)/bin/$(APP_NAME) cmd/*.go

test:
	@echo "Testing..."
	go test -v -failfast -timeout 1m -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf $(shell pwd)/bin || true
	chmod -R a+w pkg/ || true
	rm -rf $(shell pwd)/pkg || true

submodule-update:
	git submodule update --recursive --init

submodule-update-remote:
	git submodule update --recursive --init --remote

