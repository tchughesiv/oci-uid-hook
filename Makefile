# This is the Makefile for oci-uid-hook
# Authors: Tommy Hughes <tohughes@redhat.com>
#
# Targets (see each target for more information):
#   all: Build code
#   build: Build code
#   install: Install docs, install binary to specified location
#   clean: Clean up.

.PHONY:  build install clean all docs dist

all: build docs

PREFIX ?= $(DESTDIR)/usr
HOOKSDIR=/usr/libexec/oci/hooks.d
HOOKSINSTALLDIR=$(DESTDIR)$(HOOKSDIR)
# need this substitution to get build ID note
GOBUILD=go build -a -ldflags "${LDFLAGS:-} -B 0x$(shell head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')"

# Build code
#
# Example:
#   make build
oci-uid-hook: oci-uid-hook.go
	GOPATH=$$GOPATH:/usr/share/gocode $(GOBUILD) -o oci-uid-hook

oci-uid-hook.1: doc/oci-uid-hook.1.md
	go-md2man -in "doc/oci-uid-hook.1.md" -out "doc/oci-uid-hook.1"
	sed -i 's|$$HOOKSDIR|$(HOOKSDIR)|' doc/oci-uid-hook.1

docs: oci-uid-hook.1
build: oci-uid-hook

dist: oci-uid-hook.spec 
	spectool -g oci-uid-hook.spec

rpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_specdir `pwd`" \
	--define "_rpmdir `pwd`" --define "_srcrpmdir `pwd`" -ba oci-uid-hook.spec 

# Install code (change here to place anywhere you want)
#
# Example:
#   make install
install: 
	install -d -m 755 $(HOOKSINSTALLDIR)
	install -m 755 oci-uid-hook $(HOOKSINSTALLDIR)
	install -d -m 755 $(PREFIX)/share/man/man1
	install -m 644 doc/oci-uid-hook.1 $(PREFIX)/share/man/man1
	install -D -m 644 oci-uid-hook.conf $(DESTDIR)/etc/oci-uid-hook.conf
# Clean up
#
# Example:
#   make clean
clean:
	rm -f oci-uid-hook *~
	rm -f doc/oci-uid-hook.1
	rm -f oci-uid-hook-*.tar.gz
	rm -f oci-uid-hook-*.rpm