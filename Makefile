GOOS ?= "linux"
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
LINUX_ARCH = x86_64
else ifeq ($(GOARCH),arm64)
LINUX_ARCH = aarch64
endif

GITHUB_REF_NAME ?= $(shell git branch --show-current)
SHOULD_PUBLISH = $(shell echo $(GITHUB_REF_NAME) | grep -qE '^(main|v[0-9]+\.[0-9]+\.[0-9]+)$$' && echo true)

ifeq ($(shell git status -s),)
	ifeq ($(SHOULD_PUBLISH),true)
		LAST_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null)
		COMMITS_SINCE_TAG := $(shell git rev-list $(LAST_TAG)..HEAD --count 2>/dev/null)
		BASE_VERSION := $(shell echo $(LAST_TAG) | cut -c2-)
		NEXT_VERSION := $(shell echo $(BASE_VERSION) | awk -F. '{$$3+=1}1' OFS=.)
		ifeq ($(COMMITS_SINCE_TAG),0)
			TAG_VERSION ?= $(BASE_VERSION)
		else
			TAG_VERSION ?= $(NEXT_VERSION)-dev.$(COMMITS_SINCE_TAG)
		endif
	endif
	GIT_REVISION = $(shell git rev-parse HEAD | tr -d '\n')
endif
ifeq ($(TAG_VERSION),)
PATH_VERSION = custom
else
PATH_VERSION = v$(TAG_VERSION)
endif

LDFLAGS = "-s -w -X 'github.com/viamrobotics/agent/utils.Version=${TAG_VERSION}' -X 'github.com/viamrobotics/agent/utils.GitRevision=${GIT_REVISION}'"
TAGS = osusergo,netgo


.DEFAULT_GOAL := bin/viam-agent-$(PATH_VERSION)-$(LINUX_ARCH)

.PHONY: debug-workflow
debug-workflow:
	echo GITHUB_REF_NAME $(GITHUB_REF_NAME)
	echo SHOULD_PUBLISH $(SHOULD_PUBLISH)
	echo TAG_VERSION $(TAG_VERSION)
	echo PATH_VERSION $(PATH_VERSION)
	echo GIT_REVISION $(GIT_REVISION)
	echo LAST_TAG $(LAST_TAG)
	echo COMMITS_SINCE_TAG $(COMMITS_SINCE_TAG)

.PHONY: all
all: amd64 arm64

.PHONY: arm64
arm64:
	make GOARCH=arm64

.PHONY: amd64
amd64:
	make GOARCH=amd64

bin/viam-agent-$(PATH_VERSION)-$(LINUX_ARCH): go.* *.go */*.go */*/*.go *.service Makefile
	go build -o $@ -trimpath -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent/main.go
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' && cp $@ bin/viam-agent-stable-$(LINUX_ARCH) || true

.PHONY: clean
clean:
	rm -rf bin/

bin/golangci-lint: Makefile
	GOBIN=`pwd`/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5

.PHONY: lint
lint: bin/golangci-lint
	go mod tidy
	bin/golangci-lint run -v --fix

.PHONY: test
test:
	go test -race ./...

.PHONY: manifest
manifest: bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-x86_64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-aarch64

.PHONY: upload-stable
upload-stable: bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-stable-x86_64 bin/viam-agent-stable-aarch64 manifest
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-stable-x86_64 bin/viam-agent-stable-aarch64 gs://packages.viam.com/apps/viam-agent/
	gsutil cp etc/viam-agent-$(PATH_VERSION)-x86_64.json etc/viam-agent-$(PATH_VERSION)-aarch64.json gs://packages.viam.com/apps/viam-subsystems/

.PHONY: upload-installer
upload-installer:
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp preinstall.sh install.sh uninstall.sh gs://packages.viam.com/apps/viam-agent/
