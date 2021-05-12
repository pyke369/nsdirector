#!/bin/sh

# build targets
nsdirector: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o nsdirector
	@-strip nsdirector 2>/dev/null || true
	@-upx -9 nsdirector 2>/dev/null || true
clean:
	@rm -rf local remote
	@cd support && make clean && cd ..
distclean: clean
	@rm -f nsdirector *.upx
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
backend: nsdirector
	@./nsdirector backend conf/nsdirector.conf
dump: nsdirector
	@./nsdirector dump conf/nsdirector.conf
checks:
	@curl -s http://localhost:54321/checks |gron |gron -u
request:
	@dig @127.0.0.1 -p 5353 -t any entry1.domain1.com +subnet=78.193.67.0/24
	@dig @127.0.0.1 -p 5353 -t any whereami.domain1.com +subnet=78.193.67.0/24
bench: nsdirector
	@cd support && make bench && cd ..
	@./support/bench ./nsdirector backend conf/nsdirector.conf
