.PHONY: test lint build
test:
	go test -race -count=1 ./...
lint:
	golangci-lint run
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remnawave-wg-manager ./cmd/remnawave-wg-manager
