[![Build Status](https://travis-ci.org/function61/holepunch-client.svg?branch=master)](https://travis-ci.org/function61/holepunch-client)
[![Download](https://api.bintray.com/packages/function61/holepunch-client/main/images/download.svg)](https://bintray.com/function61/holepunch-client/main/_latestVersion#files)

What?
-----

This is a standalone binary for creating a semi-persistent SSH reverse tunnel.

Failed connections are automatically retried and includes a helper to add this service to system startup (Systemd).


Usage
-----

Download a suitable binary for you from the Bintray link.

First, generate a keypair for you:

```
$ ssh-keygen -t ecdsa -b 521
```

Copy content of `id_ecdsa.pub` to your SSH server's `authorized_keys` file.

Write `holepunch.json` (see `holepunch.example.json` for example)

Run client:

```
$ ./holepunch write-systemd-file
$ sudo systemctl enable holepunch
$ sudo systemctl start holepunch
$ sudo service holepunch status
```


Credits
-------

Hugely inspired by [codref's gist](https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3)


TODO
----

- Polishing
- Use [spf13/cobra](https://github.com/spf13/cobra)
- Exponential backoff on errors
- Improve error messages, handling and remove panics
