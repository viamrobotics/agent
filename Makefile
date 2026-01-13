GOOS ?= "linux"
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
LINUX_ARCH = x86_64
else ifeq ($(GOARCH),arm64)
LINUX_ARCH = aarch64
endif

OS_NAME =
ifeq ($(GOOS),windows)
	OS_NAME = -windows
endif

GIT_REVISION = $(shell git rev-parse HEAD)
TAG_VERSION ?= $(shell ./dev-version.sh | sed 's/^v//')
ifeq ($(TAG_VERSION),)
PATH_VERSION = custom
else
PATH_VERSION = v$(TAG_VERSION)
endif

LDFLAGS = "-s -w -X 'github.com/viamrobotics/agent/utils.Version=${TAG_VERSION}' -X 'github.com/viamrobotics/agent/utils.GitRevision=${GIT_REVISION}'"
TAGS = osusergo,netgo


.DEFAULT_GOAL := bin/viam-agent-$(PATH_VERSION)$(OS_NAME)-$(LINUX_ARCH)

.PHONY: all
all: amd64 arm64 windows

.PHONY: arm64
arm64:
	make GOOS=linux GOARCH=arm64

.PHONY: amd64
amd64:
	make GOOS=linux GOARCH=amd64

.PHONY: windows
windows:
	make GOOS=windows GOARCH=amd64

bin/viam-agent-$(PATH_VERSION)$(OS_NAME)-$(LINUX_ARCH): go.* *.go */*.go */*/*.go *.service Makefile
	go build -o $@ -trimpath -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' && cp $@ bin/viam-agent-stable$(OS_NAME)-$(LINUX_ARCH) || true

# Used for building agent binaries from within test suite.
.PHONY: test-build
test-build:
	@if [ -z ${TESTBUILD_OUTPUT_PATH} ]; then \
		echo "Error: must set TESTBUILD_OUTPUT_PATH for test-build make target"; \
		exit 1; \
	fi
	go build -o ${TESTBUILD_OUTPUT_PATH} -trimpath -tags $(TAGS) -ldflags	$(LDFLAGS) ./cmd/viam-agent

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: ensure-mise
ensure-mise:
	mise trust -yq
	mise install

.PHONY: lint
lint: ensure-mise
	@mise run lint

.PHONY: test
test:
	go test -race ./...

.PHONY: manifest
manifest: bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-$(PATH_VERSION)-windows-x86_64
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+' || exit 1
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-x86_64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-aarch64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-windows-x86_64

.PHONY: upload-stable
upload-stable: manifest
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-stable-x86_64 bin/viam-agent-stable-aarch64 gs://packages.viam.com/apps/viam-agent/
	gsutil cp etc/viam-agent-$(PATH_VERSION)-x86_64.json etc/viam-agent-$(PATH_VERSION)-aarch64.json gs://packages.viam.com/apps/viam-subsystems/

.PHONY: upload-installer
upload-installer:
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp preinstall.sh install.sh uninstall.sh gs://packages.viam.com/apps/viam-agent/

.PHONY: windows-installer
windows-installer:
	@./build-windows-installer-exe.sh

.PHONY: upload-windows-installer
upload-windows-installer:
	@if [ -n "$$(find . -name 'viam-agent-windows-installer*.exe')" ]; then \
		INSTALLER=$$(find . -name 'viam-agent-windows-installer*.exe'); \
		gsutil -h "Cache-Control:no-cache" cp "$$INSTALLER" gs://packages.viam.com/apps/viam-agent/; \
		echo "Uploaded: $$INSTALLER"; \
	else \
		echo "Error: No Windows installer executable found"; \
		echo "Please run 'make windows-installer' first"; \
		exit 1; \
	fi
