
=====
 kxc
=====

-------------------
Key exchange client
-------------------
:Author: Alberto Bertogli <albertito@blitiri.com.ar>
:Manual section: 1


SYNOPSIS
========

kxc --client_cert=<file> --client_key=<file> --server_cert=<file> <URL>


DESCRIPTION
===========

kxc is a client for kxd, a key exchange daemon.

It will take a client key and certificate, the expected server certificate,
and a URL to the server (like ``kxd://server/host1/key1``), and it will print
on standard output the returned key (the contents of the corresponding key
file on the server).

There are scripts to tie this with cryptsetup's infrastructure to make the
opening of encrypted devices automatic; see ``kxc-cryptsetup(1)`` for the
details.


OPTIONS
=======

--client_key=<file>
  File containing the client private key (in PAM format).

--client_cert=<file>
  File containing the client certificate that corresponds to the given key (in
  PAM format).

--server_cert=<file>
  File containing valid server certificate(s).


SEE ALSO
========

``kxc-cryptsetup(1)``, ``kxd(1)``.


BUGS
====

If you want to report bugs, or have any questions or comments, just let me
know. For more information, you can go to http://blitiri.com.ar/p/kxd.

