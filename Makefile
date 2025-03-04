GOOS ?= "linux"
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
LINUX_ARCH = x86_64
else ifeq ($(GOARCH),arm64)
LINUX_ARCH = aarch64
endif

TAG_VERSION ?= $(shell dev-version.sh | sed 's/^v//')
ifeq ($(TAG_VERSION),)
PATH_VERSION = custom
else
PATH_VERSION = v$(TAG_VERSION)
endif

LDFLAGS = "-s -w -X 'github.com/viamrobotics/agent/utils.Version=${TAG_VERSION}' -X 'github.com/viamrobotics/agent/utils.GitRevision=${GIT_REVISION}'"
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
