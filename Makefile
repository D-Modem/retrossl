GO ?= go

all: test

# gofmt, vet and the tests, as CI runs them
test:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: the files above need formatting"; exit 1; }
	$(GO) vet ./...
	$(GO) test -race ./...

# the tests' coverage, as cover.html
cover:
	$(GO) test -coverprofile=cover.out ./...
	$(GO) tool cover -html=cover.out -o cover.html
	@$(GO) tool cover -func=cover.out | tail -1

fmt:
	gofmt -w .

clean:
	rm -f cover.out cover.html

.PHONY: all test cover fmt clean
