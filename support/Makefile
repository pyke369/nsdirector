#!/bin/sh

# build targets
bench: bench.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; go build -trimpath -o bench bench.go && strip bench
clean:
distclean: clean
	@rm -f bench
