#!/bin/sh

# build targets
nsdirector: *.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; go build -trimpath -o nsdirector && strip nsdirector
clean:
	@rm -rf local remote
	@cd support && make clean && cd ..
distclean: clean
	@rm -f nsdirector
	@cd support && make distclean && cd ..
deb:
	@debuild -e GOROOT -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../nsdirector_*

# run targets
pack: nsdirector
	@mkdir -p remote
	@./nsdirector pack conf/domains remote/domains
fetch: nsdirector
	@./nsdirector fetch http://localhost/domains local/domains
pdns: nsdirector
	@pdns_server --config-dir=conf
run: nsdirector
	@./nsdirector backend conf/nsdirector.conf
dump: nsdirector
	@./nsdirector dump conf/nsdirector.conf
checks:
	@curl -s http://localhost:54321/checks |gron |gron -u
request:
	@dig @127.0.0.1 -p 5353 -t any entry1.domain1.com +subnet=78.193.67.0/24
bench: nsdirector
	@cd support && make bench && cd ..
	@./support/bench ./nsdirector backend conf/nsdirector.conf
