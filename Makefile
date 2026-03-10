VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"
BINARY  := leakcheck
CMD     := ./cmd/leakcheck

.PHONY: build run test install release clean help

build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

run:
	go run $(LDFLAGS) $(CMD)

test:
	go test -v -race ./...

install: build
	mv $(BINARY) /usr/local/bin/$(BINARY)
	@echo "✓ Installed to /usr/local/bin/$(BINARY)"

release:
	@mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   $(CMD)
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64   $(CMD)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(CMD)
	@echo "✓ Binaries built in dist/"

clean:
	rm -f $(BINARY)
	rm -rf dist/

help:
	@echo ""
	@echo "  $(BINARY) $(VERSION)"
	@echo ""
	@grep -E '^[a-z]+:' Makefile | sed 's/:.*//' | sed 's/^/  make /'
	@echo ""
