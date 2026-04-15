GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
ifeq ($(GOARCH),amd64)
ARCH = x86_64
else ifeq ($(GOARCH),arm64)
ARCH = aarch64
endif

OS_NAME =
ifeq ($(GOOS),windows)
	OS_NAME = -windows
else ifeq ($(GOOS),darwin)
	OS_NAME = -darwin
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


.DEFAULT_GOAL := bin/viam-agent-$(PATH_VERSION)$(OS_NAME)-$(ARCH)

.PHONY: all
all: amd64 arm64 windows darwin

.PHONY: arm64
arm64:
	make GOOS=linux GOARCH=arm64

.PHONY: amd64
amd64:
	make GOOS=linux GOARCH=amd64

.PHONY: windows
windows:
	make GOOS=windows GOARCH=amd64

.PHONY: darwin
darwin:
	make GOOS=darwin GOARCH=arm64

bin/viam-agent-$(PATH_VERSION)$(OS_NAME)-$(ARCH): go.* *.go */*.go */*/*.go *.service Makefile
	go build -o $@ -trimpath -tags $(TAGS) -ldflags $(LDFLAGS) ./cmd/viam-agent
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' && cp $@ bin/viam-agent-stable$(OS_NAME)-$(ARCH) || true

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

.PHONY: fmt-sh
fmt-sh: ensure-mise
	@mise run fmt-sh

.PHONY: test
test:
	go test -race ./...

.PHONY: manifest
manifest: bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-$(PATH_VERSION)-windows-x86_64 bin/viam-agent-$(PATH_VERSION)-darwin-aarch64
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+' || exit 1
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-x86_64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-aarch64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-windows-x86_64
	./manifest.sh bin/viam-agent-$(PATH_VERSION)-darwin-aarch64

.PHONY: upload-stable
upload-stable: manifest
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp bin/viam-agent-$(PATH_VERSION)-x86_64 bin/viam-agent-$(PATH_VERSION)-aarch64 bin/viam-agent-$(PATH_VERSION)-darwin-aarch64 bin/viam-agent-stable-x86_64 bin/viam-agent-stable-aarch64 bin/viam-agent-stable-darwin-aarch64 gs://packages.viam.com/apps/viam-agent/
	gsutil cp etc/viam-agent-$(PATH_VERSION)-x86_64.json etc/viam-agent-$(PATH_VERSION)-aarch64.json etc/viam-agent-$(PATH_VERSION)-darwin-aarch64.json gs://packages.viam.com/apps/viam-subsystems/

.PHONY: upload-installer
upload-installer:
	echo $(PATH_VERSION) | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$' || exit 1
	gsutil -h "Cache-Control:no-cache" cp preinstall.sh install.sh uninstall.sh gs://packages.viam.com/apps/viam-agent/

.PHONY: lint-ps
lint-ps:
	# I installed from .deb in releases here https://github.com/PowerShell/PowerShell
	# note: this linter is not incredibly useful; for example it won't catch some missing reference errors. Don't over-rely
	@echo "Checking for non-ASCII characters (breaks PS 5.1 without BOM)..."
	@if grep -Pn '[^\x00-\x7F]' windows-installer-agent.ps1; then echo "ERROR: non-ASCII characters found above — PS 5.1 will misparse"; exit 1; fi
	pwsh -Command 'if (-not (Get-Module PSScriptAnalyzer -ListAvailable)) { Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -ErrorAction Stop }; Invoke-ScriptAnalyzer -Path windows-installer-agent.ps1 -Settings PSScriptAnalyzerSettings.psd1 -Severity Warning,Error -EnableExit'

.PHONY: windows-installer
windows-installer:
	@./build-windows-installer-exe.sh

# MSI installer build (requires Windows with .NET + WiX)
# WiX path validation does not work on Linux.
# 1. Downloads the agent exe from GCS (same URL as the ps1 installer)
# 2. Builds the MSI with WiX v6
.PHONY: msi
msi: msi/viam-agent.msi

msi/viam-agent.msi: msi/Package.wxs msi/Package.wixproj
	@echo "Downloading agent executable for MSI bundle..."
	@mkdir -p msi/agent-bin
	@curl -fsSL -o msi/agent-bin/viam-agent-from-installer.exe \
		"https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-windows-x86_64"
	@echo "Building MSI..."
	dotnet tool restore
	cd msi && dotnet build -p:AgentBinDir=agent-bin -c Release
	@cp msi/bin/Release/*.msi msi/viam-agent.msi 2>/dev/null || \
		cp msi/bin/x64/Release/*.msi msi/viam-agent.msi 2>/dev/null || \
		echo "WARNING: could not find output .msi -- check msi/bin/ for output location"
	@echo "MSI built: msi/viam-agent.msi"

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
