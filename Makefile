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

bin/viam-agent-$(PATH_VERSION)-$(LINUX_ARCH): go.* *.go */*.go */*/*.go subsystems/viamagent/*.service
	go build -o $@ -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent/main.go

bin/viam-agent.xz: bin/viam-agent
	xz -vkf bin/viam-agent

.PHONY: upx
upx: bin/viam-agent
	upx --best --lzma bin/viam-agent

.PHONY: clean
clean:
	rm -rf bin/

bin/golangci-lint:
	GOBIN=`pwd`/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: lint
lint: bin/golangci-lint
	bin/golangci-lint run -v --fix
	go mod tidy
