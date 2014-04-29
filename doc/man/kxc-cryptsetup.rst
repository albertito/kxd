
================
 kxc-cryptsetup
================

------------------------
Cryptsetup helper to kxc
------------------------

:Author: Alberto Bertogli <albertito@blitiri.com.ar>
:Manual section: 1


SYNOPSIS
========

kxc-cryptsetup <NAME>


DESCRIPTION
===========

``kxc(1)`` is a client for kxd, a key exchange daemon.

kxc-cryptsetup is a convenience wrapper for invoking kxc while taking the
options from the files in ``/etc/kxc/``.

It can be used as a cryptsetup keyscript, to automatically get keys to open
encrypted devices with kxc.


OPTIONS
=======

Its only command-line argument is a descriptive name, which will be used to
find the configuration files.


FILES
=====

For a given *NAME* that is passed as the only command-line argument, the
following files are needed:

/etc/kxc/NAME.key.pem
  Private key to use.

/etc/kxc/NAME.cert.pem
  Certificate to use. Must match the given key.

/etc/kxc/NAME.server_cert.pem
  Server certificate, used to validate the server.

/etc/kxc/NAME.url
  Contains the URL to the key; usually in the form of ``kxd://server/name``.


SEE ALSO
========

``kxc(1)``, ``kxd(1)``, ``crypttab(5)``, ``cryptsetup(8)``.


BUGS
====

If you want to report bugs, or have any questions or comments, just let me
know. For more information, you can go to http://blitiri.com.ar/p/kxd.

