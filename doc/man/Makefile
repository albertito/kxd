
default: manpages

%.1: %.rst
	rst2man < $^ > $@

manpages: kxd.1 kxc.1 kxc-cryptsetup.1

clean:
	rm -f kxd.1 kxc.1 kxc-cryptsetup.1

