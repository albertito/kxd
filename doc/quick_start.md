
# Quick start

In this guide we show how to set up a [key exchange daemon][kxd] and client
on a typical scenario where the keys are used to open a device encrypted with
[dm-crypt] \(the standard Linux disk encryption).

These steps have been checked on a Debian install, other distributions should
be similar but may differ on some of the details (specially on the
[Configuring crypttab] section).

- `server` is the hostname of the server.
- `client` is the hostname of the client.
- `sda2` is the encrypted drive.


## Server setup

Install [kxd] on the server, via your distribution packages (e.g. `apt install
kxd`), or directly from source.

Then, run `create-kxd-config <hostname>`, which will create the configuration
directories, and generate a [self-signed] key/cert pair for the server (valid
for 10 years).

For the hostname, use the name or IP that the clients will use to reach the
server. You can use more than one, separated with commas.


## Client setup

Install [kxc][kxd] on the client machine, via your distribution packages (e.g.
`apt install kxc`), or directly from source.

Then, run `kxc-add-key server sda2`, which will create the configuration
directories, generate the client key/cert pair (valid for 10 years), and also
create an entry for an `client/sda2` key to be fetched from the server.
Everything is in `/etc/kxc/`.

Finally, copy the server public certificate over, using
`scp server:/etc/kxd/cert.pem /etc/kxc/sda2.server_cert.pem` (or something
equivalent).


## Adding the key to the server

On the server, run `kxd-add-client-key client sda2` to generate the basic
configuration for that client's key, including the key itself (generated
randomly).

Then, copy the client public certificate over, using
`scp client:/etc/kxc/cert.pem /etc/kxd/data/client/sda2/allowed_clients`
(or something equivalent).

That allows the client to fetch the key.


## Updating the drive's key

On the client, run `kxc-cryptsetup sda2 | wc -c` to double-check that the
output length is as expected (you could also compare it by running sha256 or
something equivalent).

Assuming that goes well, all you need is to add that key to your drives' key
ring so it can be decrypted with it:

```shell
# Note we copy to /dev/shm which should not be written to disk.
kxc-cryptsetup sda2 > /dev/shm/key

cryptsetup luksAddKey /dev/sda2 /dev/shm/key

rm /dev/shm/key
```

Note this *adds* a new key, but your existing ones are still valid. Always
have more than one key, so if something goes wrong with kxd, you can still
unlock the drive manually.


## Configuring crypttab

In order to get kxc to be run automatically to fetch the key, we need to edit
`/etc/crypttab` and tell it to use a keyscript:

```
sda2_crypt UUID=blah-blah-blah sda2 luks,keyscript=/usr/bin/kxc-cryptsetup
                               ^^^^      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

Note the `sda2` field corresponds to the name we've been passing around in
previous sections. The `keyscript=/usr/bin/kxc-cryptsetup` option is our way
of telling the cryptsetup infrastructure to use our script to fetch the key
for this target.


You can test that this works by using:

```shell
cryptdisks_stop sda2_crypt
cryptdisks_start sda2_crypt
```

The second command should issue a request to your server to get the key.

Consider running `update-initramfs -u` if your device is the root device, or
it is needed very early in the boot process.


[kxd]: https://blitiri.com.ar/p/kxd
[kxc]: https://blitiri.com.ar/p/kxd
[dm-crypt]: https://en.wikipedia.org/wiki/dm-crypt
[self-signed]: https://en.wikipedia.org/wiki/Self-signed_certificate

