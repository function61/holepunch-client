[![Build Status](https://img.shields.io/travis/function61/holepunch-client.svg?style=for-the-badge)](https://travis-ci.org/function61/holepunch-client)
[![Download](https://img.shields.io/bintray/v/function61/holepunch-client/main.svg?style=for-the-badge&label=Download)](https://bintray.com/function61/holepunch-client/main/_latestVersion#files)

What?
-----

This is a standalone binary for creating a semi-persistent SSH reverse tunnel.

Failed connections are automatically retried and includes a helper to add this service to system startup (Systemd).


Usage
-----

Download a suitable binary for you from the Bintray link.

First, generate a keypair for you:

```
$ ssh-keygen -t ecdsa -b 521 -C "my awesome private key" -f id_ecdsa
```

Copy content of `id_ecdsa.pub` to your SSH server's `authorized_keys` file.

Write `holepunch.json` (see `holepunch.example.json` for example). You can use this with a
vanilla SSH server, but if you're using
[function61/holepunch-server](https://github.com/function61/holepunch-server), you can also
connect via WebSocket if you use format like `ws://example.com/_ssh` in server address.

Run client:

```
$ ./holepunch write-systemd-file
$ sudo systemctl enable holepunch
$ sudo systemctl start holepunch
$ sudo systemctl status holepunch
```


Credits
-------

Hugely inspired by [codref's gist](https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3)


TODO
----

- Exponential backoff on errors
- Implement `FixedHostKey` (ssh.HostKeyCallback) instead of the insecure one
