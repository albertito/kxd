
=====
 kxd
=====

-------------------
Key exchange daemon
-------------------

:Author: Alberto Bertogli <albertito@blitiri.com.ar>
:Manual section: 1


SYNOPSIS
========

kxd [--key=<file>] [--cert=<file>] [--data_dir=<directory>]
[--email_from=<email-address>] [--ip_addr=<ip-address>] [--logfile=<file>]
[--port=<port>] [--smtp_addr=<host:port>]


DESCRIPTION
===========

kxd is a key exchange daemon, which serves blobs of data (keys) over https.

It can be used to get keys remotely instead of using local storage.
The main use case is to get keys to open dm-crypt devices automatically,
without having to store them on the local machine.


SETUP
=====

The server configuration is stored in a root directory (``/etc/kxd/data/`` by
default), and within there, with per-key directories (e.g.
``/etc/kxd/data/host1/key1/``), each containing the following files:

  - ``key``: Contains the key to give to the client.
  - ``allowed_clients``: Contains one or more PEM-encoded client certificates
    that will be allowed to request the key.
    If not present, then no clients will be allowed to access this key.
  - ``allowed_hosts``: Contains one or more host names (one per line).
    If not present, then all hosts will be allowed to access that key (as long
    as they are authorized with a valid client certificate).
  - ``email_to``: Contains one or more email destinations to notify (one per
    line).  If not present, then no notifications will be sent upon key
    accesses.


OPTIONS
=======

--key=<file>
  Private key to use.
  Defaults to /etc/kxd/key.pem.

--cert=<file>
  Certificate to use; must match the given key.
  Defaults to /etc/kxd/cert.pem.

--data_dir=<directory>
  Data directory, where the key and configuration live (see the SETUP section
  above).
  Defaults to /etc/kxd/data.

--email_from=<email-address>
  Email address to send email from.

--ip_addr=<ip-address>
  IP address to listen on.
  Defaults to 0.0.0.0, which means all.

--logfile=<file>
  File to write logs to, use '-' for stdout.
  By default, the daemon will log to syslog.

--port=<port>
  Port to listen on.
  The default port is 19840.

--smtp_addr=<host:port>
  Address of the SMTP server to use to send emails.
  If none is given, then emails will not be sent.


FILES
=====

/etc/kxd/key.pem
  Private key to use for SSL.

/etc/kxd/cert.pem
  Certificate to use for SSL. Must match the given private key.

/etc/kxd/data/
  Directory where the keys and their configuration are stored.


SEE ALSO
========

``kxc(1)``, ``kxc-cryptsetup(1)``.


BUGS
====

If you want to report bugs, or have any questions or comments, just let me
know. For more information, you can go to http://blitiri.com.ar/p/kxd.

