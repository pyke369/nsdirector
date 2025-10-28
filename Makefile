#!/bin/sh

PROGNAME=nsdirector

# build targets
$(PROGNAME): *.go
	@env GOPATH=/tmp/go go get && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o $(PROGNAME)
	@-strip $(PROGNAME) 2>/dev/null || true
	@-#upx -9 $(PROGNAME) 2>/dev/null || true
lint:
	@-go vet ./... || true
	@-staticcheck ./... || true
	@-gocritic check -enableAll ./... || true
	@-govulncheck ./... || true
clean:
	@rm -rf local remote
distclean: clean
	@rm -rf $(PROGNAME) *.upx

# run targets
pack: $(PROGNAME)
	@mkdir -p remote
	@./nsdirector pack conf/domains remote/domains
fetch: $(PROGNAME)
	@./nsdirector fetch http://localhost:8000/domains local/domains
pdns: $(PROGNAME)
	@pdns_server --config-dir=conf
backend: $(PROGNAME)
	@./nsdirector backend conf/nsdirector.conf
dump: $(PROGNAME)
	@./nsdirector dump conf/nsdirector.conf
check:
	@gron http://localhost:54321/check |gron -u
request:
	@dig @127.0.0.1 -p 1053 -t any entry1.domain1.com +subnet=78.193.67.0/24
	@dig @127.0.0.1 -p 1053 -t srv _mysrv._tcp.domain1.com +subnet=78.193.67.0/24
	@dig @127.0.0.1 -p 1053 -t txt whereami.domain1.com +subnet=78.193.67.0/24
