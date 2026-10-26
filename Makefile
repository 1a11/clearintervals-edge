GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
.PHONY: verify test build generate vectors fuzz scan integration
verify:
	@test -z "$$($(GO) fmt ./...)"
	@test -z "$$(gofmt -l integration)"
	$(GO) vet ./...
	$(GO) test -race -timeout 90s ./...
test:
	$(GO) test -race -timeout 90s ./...
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o bin/edgegateway ./cmd/edgegateway
generate:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	python -m grpc_tools.protoc -I . --plugin=protoc-gen-go=$$($(GO) env GOPATH)/bin/protoc-gen-go --go_out=. --go_opt=paths=source_relative protocol/v1/uplink.proto
vectors:
	$(GO) run ./tools/vectors > protocol/v1/vectors.json
	python -m grpc_tools.protoc -I . --python_out=/tmp protocol/v1/uplink.proto
	PYTHONPATH=/tmp:$${PYTHONPATH} python tools/check_vectors.py
fuzz:
	$(GO) test ./internal/wire -run='^$$' -fuzz=FuzzRead -fuzztime=20s -parallel=2
	$(GO) test ./internal/remotewrite -run='^$$' -fuzz=FuzzRemoteWrite -fuzztime=20s -parallel=2
scan:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
integration:
	python integration/fixture.py --output build/acceptance-process.json
