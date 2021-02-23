![Build status](https://github.com/function61/holepunch-client/workflows/Build/badge.svg)
[![Download](https://img.shields.io/github/downloads/function61/holepunch-client/total.svg?style=for-the-badge)](https://github.com/function61/holepunch-client/releases)

What?
-----

UPDATE: You might be best served by mesh VPN like Tailscale (or WireGuard), they can even expose subnets.


This is a standalone binary for creating a semi-persistent (client tries its best to
detect errors, use keepalives and do reconnects) SSH reverse tunnel.

You can use the native OpenSSH server as a server, or
[function61/holepunch-server](https://github.com/function61/holepunch-server) which brings
some fancier optional features like purely-over-HTTP operation.

Failed connections are automatically retried and includes a helper to add this service to system startup (Systemd).


Usage
-----

Download a suitable binary (we support Linux/AMD64, Linux/ARM and Windows/AMD64) for you
from the download link.

First, generate a keypair for you:

```console
$ ssh-keygen -t ecdsa -b 521 -C "my awesome private key" -f id_ecdsa
```

Copy content of `id_ecdsa.pub` to your SSH server's `authorized_keys` file.

Write `holepunch.json` (see [holepunch.example.json](holepunch.example.json)).
You can use this with a vanilla SSH server, but if you're using
[function61/holepunch-server](https://github.com/function61/holepunch-server), you can also
connect via WebSocket if you use format like `ws://example.com/_ssh` as server address
(or `wss://` for https).

Run client:

```console
$ ./holepunch connect
```

To exit, type `Ctrl + c` for graceful stop.

To make holepunch automatically start on system startup (and restart on crashes):

```console
$ ./holepunch write-systemd-file
Wrote unit file to /etc/systemd/system/holepunch.service
Run to enable on boot & to start now:
        $ systemctl enable holepunch
        $ systemctl start holepunch
        $ systemctl status holepunch
```


How to build & develop
----------------------

[How to build & develop](https://github.com/function61/turbobob/blob/master/docs/external-how-to-build-and-dev.md)
(with Turbo Bob, our build tool). It's easy and simple!

If you prefer to not install Turbo Bob, standard Go build commands work
([instructions here](https://github.com/function61/holepunch-client/issues/10#issuecomment-634530149)).


Credits
-------

Hugely inspired by [codref's gist](https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3)
