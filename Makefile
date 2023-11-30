GOOS ?= "linux"
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
LINUX_ARCH = x86_64
else ifeq ($(GOARCH),arm64)
LINUX_ARCH = aarch64
endif

GIT_REVISION = $(shell git rev-parse HEAD | tr -d '\n')
TAG_VERSION ?= $(shell tag=`git tag --points-at | sort -Vr | head -n1`; echo ${tag:1})
ifeq ($(TAG_VERSION),)
PATH_VERSION = custom
else
PATH_VERSION = v$(TAG_VERSION)
endif

LDFLAGS = "-s -w -X 'github.com/viamrobotics/agent/subsystems/viamagent.Version=${TAG_VERSION}' -X 'github.com/viamrobotics/agent/subsystems/viamagent.GitRevision=${GIT_REVISION}'"
TAGS = osusergo,netgo


.DEFAULT_GOAL := bin/viam-agent-$(PATH_VERSION)-$(LINUX_ARCH)

.PHONY: all
all: amd64 arm64

.PHONY: arm64
arm64:
	make GOARCH=arm64

.PHONY: amd64
amd64:
	make GOARCH=amd64

bin/viam-agent-$(PATH_VERSION)-$(LINUX_ARCH): go.* *.go */*.go */*/*.go subsystems/viamagent/*.service
	go build -o $@ -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent/main.go

.PHONY: clean
clean:
	rm -rf bin/

bin/golangci-lint:
	GOBIN=`pwd`/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2

.PHONY: lint
lint: bin/golangci-lint
	bin/golangci-lint run -v --fix
	go mod tidy
