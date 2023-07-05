.DEFAULT_GOAL := bin/viam-agent.xz

bin/viam-agent: go.* *.go */*.go */*/*.go
	go build -o bin/viam-agent -tags osusergo,netgo -ldflags "-s -w" ./cmd/viam-agent/main.go

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
