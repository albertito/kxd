
GO = go
OUTDIR = ./out

default: kxd kxc kxgencert

kxd:
	$(GO) build -o $(OUTDIR)/kxd ./kxd

kxgencert:
	$(GO) build -o $(OUTDIR)/kxgencert ./kxgencert

# For the client, because it can be run in a very limited environment without
# glibc (like initramfs), we build it using the native go networking so it can
# work even when glibc's resolvers are missing.
kxc:
	$(GO) build --tags netgo -a -o $(OUTDIR)/kxc ./kxc

fmt:
	gofmt -s -w .
	black -l 80 tests/run_tests

vet:
	$(GO) vet ./...

test: kxd kxc kxgencert
	tests/run_tests -b

tests: test


# Prefixes for installing the files.
PREFIX=/usr
ETCDIR=/etc
SYSTEMDDIR=$(shell pkg-config systemd --variable=systemdsystemunitdir)

# Install utility, we assume it's GNU/BSD compatible.
INSTALL=install

install-all: install-kxd install-kxc install-kxgencert \
	install-init.d install-initramfs

install-kxd: kxd
	$(INSTALL) -d $(PREFIX)/bin
	$(INSTALL) -m 0755 out/kxd $(PREFIX)/bin/
	$(INSTALL) -m 0755 scripts/create-kxd-config $(PREFIX)/bin/
	$(INSTALL) -m 0755 scripts/kxd-add-client-key $(PREFIX)/bin/

install-kxgencert: kxgencert
	$(INSTALL) -d $(PREFIX)/bin
	$(INSTALL) -m 0755 out/kxgencert $(PREFIX)/bin/

install-init.d: install-kxd
	$(INSTALL) -m 0755 scripts/init.d/kxd $(ETCDIR)/init.d/kxd
	$(INSTALL) -m 0644 scripts/default/kxd $(ETCDIR)/default/kxd

install-systemd: install-kxd
	$(INSTALL) -m 0644 scripts/default/kxd $(ETCDIR)/default/kxd
	$(INSTALL) -m 0644 scripts/systemd/kxd.service $(SYSTEMDDIR)

install-upstart: install-kxd
	$(INSTALL) -m 0644 scripts/default/kxd $(ETCDIR)/default/kxd
	$(INSTALL) -m 0644 scripts/upstart/kxd.conf $(ETCDIR)/init/

install-kxc: kxc
	$(INSTALL) -m 0755 out/kxc $(PREFIX)/bin/
	$(INSTALL) -m 0755 cryptsetup/kxc-cryptsetup $(PREFIX)/bin/
	$(INSTALL) -m 0755 scripts/kxc-add-key $(PREFIX)/bin/

install-initramfs: install-kxc
	$(INSTALL) -d $(PREFIX)/share/initramfs-tools/hooks/
	$(INSTALL) -m 0755 cryptsetup/initramfs-hooks/kxc \
		$(PREFIX)/share/initramfs-tools/hooks/
	$(INSTALL) -d $(PREFIX)/share/initramfs-tools/scripts/init-premount
	$(INSTALL) -m 0755 cryptsetup/initramfs-scripts/kxc-premount-net \
		$(PREFIX)/share/initramfs-tools/scripts/init-premount/


.PHONY: kxd kxc kxgencert
.PHONY: install-all install-kxd install-init.d install-kxc install-initramfs
.PHONY: test tests

