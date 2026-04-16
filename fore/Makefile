BINARY := foresight
VERSION ?= 0.1.0-dev
LDFLAGS := -X main.Version=$(VERSION)

.PHONY: all build test tidy clean install info demo

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/foresight

test:
	go test ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

install: build
	go install -ldflags "$(LDFLAGS)" ./cmd/foresight

# Quick sanity check — prints registered analyzers.
info: build
	./bin/$(BINARY) info

# Run against the sample fixture in dry-parse mode (no cluster needed).
demo: build
	./bin/$(BINARY) analyze -f test/fixtures/istio-authpolicy.yaml --dry-parse
