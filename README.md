
# Key exchange daemon

[kxd](https://blitiri.com.ar/p/kxd) is a key exchange daemon, and
corresponding client, which serves blobs of data (keys) over https.

It can be used to get keys remotely instead of using local storage.
The main use case is to get keys to open dm-crypt devices automatically,
without having to store them on the local machine.

[![Travis-CI build status](https://travis-ci.org/albertito/kxd.svg?branch=master)](https://travis-ci.org/albertito/kxd)


## Quick start

Please see the [quick start](https://blitiri.com.ar/p/kxd/docs/quick_start)
document for a step by step guide of a typical server and client setups.


## Server configuration

The server configuration is stored in a root directory (`/etc/kxd/data`), and
within there, with per-key directories (e.g. `/etc/kxd/data/host1/key1`), each
containing the following files:

- `key`: Contains the key to give to the client.
- `allowed_clients`: Contains one or more PEM-encoded client certificates
  that will be allowed to request the key.  If not present, then no clients
  will be allowed to access this key.
- `allowed_hosts`: Contains one or more host names (one per line).  If not
  present, then all hosts will be allowed to access that key (as long as they
  are authorized with a valid client certificate).
- `email_to`: Contains one or more email destinations to notify (one per
  line).  If not present, then no notifications will be sent upon key
  accesses.


## Client configuration

The basic command line client (*kxc*) will take the client key and
certificate, the expected server certificate, and a URL to the server (like
`kxd://server/host1/key1`), and it will print on standard output the returned
key (the contents of the corresponding key file).

There are scripts to tie this with cryptsetup's infrastructure to make the
opening of encrypted devices automatic; see `cryptsetup/` for the details.


## Security

All traffic between the server and the clients goes over SSL, using the
provided server certificate.

The clients are authenticated and authorized based on their SSL client
certificates matching the ones associated with the key in the server
configuration, not using a root of trust (for now).

Likewise, the clients will authenticate the server based on a certificate
given on the command line, and will only accept keys from it.

Note the server will return reasonably detailed information on errors, for
example it will tell when a key is not found vs. when the client is not
allowed. While this leaks some information about existence of keys, it makes
troubleshooting much easier.

The server itself makes no effort to protect the data internally; for example,
there is no on-disk encryption, and memory is not locked. We work under the
assumption that the server's host is secure and trusted.


## Dependencies

There are no runtime dependencies for the kxd and kxc binaries.

Building requires Go 1.11.

The configuration helper scripts (`create-kxd-config`, `kxc-add-key`, etc.)
depend on: `bash`, `openssl` (the binary), and core utilities (`mkdir`, `dd`,
etc.).

Testing needs Python 3, and openssl (the binary).


## Bugs and contact

Please report bugs to albertito@blitiri.com.ar.

The latest version can be found at
[https://blitiri.com.ar/p/kxd/](https://blitiri.com.ar/p/kxd/)

