GOOS ?= "linux"
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
LINUX_ARCH = x86_64
else ifeq ($(GOARCH),arm64)
LINUX_ARCH = aarch64
endif

GIT_REVISION = $(shell git rev-parse HEAD | tr -d '\n')
TAG_VERSION ?= $(shell git tag --points-at | sort -Vr | head -n1 | cut -c2-)
ifeq ($(TAG_VERSION),)
PATH_VERSION = custom
else
PATH_VERSION = v$(TAG_VERSION)
endif

LDFLAGS = "-s -w -X 'github.com/viamrobotics/agent-provisioning.Version=${TAG_VERSION}' -X 'github.com/viamrobotics/agent-provisioning.GitRevision=${GIT_REVISION}'"
TAGS = osusergo,netgo

.DEFAULT_GOAL := bin/viam-agent-provisioning-$(PATH_VERSION)-$(LINUX_ARCH)

.PHONY: all
all: amd64 arm64

.PHONY: arm64
arm64:
	make GOARCH=arm64

.PHONY: amd64
amd64:
	make GOARCH=amd64

bin/viam-agent-provisioning-$(PATH_VERSION)-$(LINUX_ARCH): go.* *.go */*.go */*/*.go portal/templates/*
	go build -o $@ -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent-provisioning/main.go
	test "$(PATH_VERSION)" != "custom" && cp $@ bin/viam-agent-provisioning-stable-$(LINUX_ARCH) || true

.PHONY: clean
clean:
	rm -rf bin/

bin/golangci-lint:
	GOBIN=`pwd`/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2

.PHONY: lint
lint: bin/golangci-lint
	go mod tidy
	bin/golangci-lint run -v --fix
