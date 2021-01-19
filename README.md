`nsdirector` is a [PowerDNS](https://doc.powerdns.com/authoritative/appendices/backend-writers-guide.html) advanced geodns backend written in Go.

### _Build & Packaging_
You need to install a recent version of the [Golang](https://golang.org/dl/) compiler (>= 1.15) and the GNU [make](https://www.gnu.org/software/make) utility to build the `nsdirector` binary. Once these requirements are fulfilled, clone the `nsdirector` Github repository locally:
```
$ git clone https://github.com/pyke369/nsdirector
```
and type:
```
$ make
```
This will take care of building everything. You may optionally produce a Debian binary package by typing:
```
$ make deb
```
(the [devscripts](https://packages.debian.org/fr/sid/devscripts) package needs to be installed for this last
command to work)

### _Configuration_


### _Performances_
TBD

### _License_
MIT - Copyright (c) 2019 Pierre-Yves Kerembellec
