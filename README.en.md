# csq-socks

[Русский](README.md) | **English**

Connect a Linux or Windows machine to a **csqtt** server (2.1 or 2.5) from the command line: paste the `csqtt://`
link you were given, and use the tunnel either as a **SOCKS5 proxy** or as a **full tunnel** for all traffic.

Linux x86_64, glibc 2.34+ (Ubuntu 22.04+, Debian 12+), root (sudo); or Windows 10/11 x64 — see [Windows](#windows).
Needs access to VK: csqtt gets its relays through VK calls.

## Install

```bash
curl -fsSL https://github.com/SanityProtocol/csq-socks/releases/latest/download/csq-socks.tar.gz | tar xz -C /tmp && sudo /tmp/csq-socks/install.sh
```

The same command updates an installed copy. Without internet on that machine: download `csq-socks.tar.gz` from
[Releases](https://github.com/SanityProtocol/csq-socks/releases), copy it over, then
`tar xzf csq-socks.tar.gz && sudo csq-socks/install.sh`.

Remove: `sudo /opt/csq-socks/install.sh uninstall` — the saved link and settings (`~/.config/csq-socks`) go with it.

## Use

```bash
csq-socks set      # paste your csqtt:// link, press Enter (saved to ~/.config/csq-socks/conn.json, only you can read it)
csq-socks up       # SOCKS5 proxy on 127.0.0.1:1089  (csq-socks up 1095 = another port)
csq-socks tun      # or: ALL traffic through the tunnel, nothing to configure
csq-socks status   # connected or not, your exit IP, the client's last log lines
csq-socks down     # disconnect, everything back to normal
```

**Proxy mode (`up`)** changes nothing on the system: only what you point at `127.0.0.1:1089` uses the tunnel.

- Firefox: Settings → Network Settings → Manual proxy → SOCKS Host `127.0.0.1`, Port `1089`, SOCKS v5,
  tick *Proxy DNS when using SOCKS v5*.
- Chrome: `google-chrome --proxy-server="socks5://127.0.0.1:1089"` (with no other Chrome window open).
- ssh: `ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1089 %h %p' user@host`
- curl: `curl --socks5-hostname 127.0.0.1:1089 https://ifconfig.me`

**Full tunnel (`tun`)** sends all traffic, DNS included, through csqtt; your local network stays reachable. The client
runs as system user `csqs`, and only its own VK traffic goes out directly. If the tunnel drops, traffic is **blocked**,
not leaked, until `csq-socks down`. Turn other VPNs off first: while `tun` is up it takes priority over them.

## Settings

```bash
csq-socks set -mtu 1400 -dns tls://9.9.9.9#dns.quad9.net   # with a link saved, only the settings change
csq-socks set -dns default                                  # one setting back to its default
csq-socks set -reset                                        # all of them
csq-socks set -hash "HASH1 HASH2,HASH3"                      # add VK call hashes to the saved link
```

| setting | default | |
|---|---|---|
| `-mtu` | 1500 | 576–1500: the tunnel's packet size. Lower it if pages stall while small requests work. |
| `-dns` | `default` | `up`: the server's DNS; `tun`: your system's DNS, through the tunnel. Or an IP (`1.1.1.1`, `1.1.1.1,8.8.8.8`), DoT `tls://IP[#name]`, or DoH `https://…` (on Linux `up` only). IPv4 only: the tunnel carries no IPv6. In `tun` on Linux, a DNS setting needs systemd-resolved (Ubuntu, most desktops). |
| `-port` | 1089 | the proxy's port (`csq-socks up 1095` still picks one for a single run) |
| `-streams` | 10 | 3–100 parallel csqtt streams |

The settings stay in `~/.config/csq-socks/settings.json`; a new link keeps them. `csq-socks status` shows them.

`-hash` adds VK call hashes to the link already saved: space or comma separated, or as a call link
(`…/call/join/<hash>`); the flag can repeat, duplicates are skipped. They are taken at the next `up`/`tun`.

## Good to know

- **The link picks the client.** A readable `csqtt://connect?…` link is a 2.1 server; a long scrambled `csqtt://…`
  link is a 2.5 server. A 2.1 link only works with a 2.1 server, a 2.5 link only with a 2.5 server.
- **A 2.1 link is tied to one device.** If the same link is already used in an app (LaLune, FOCSQ, the phone app),
  a 2.1 server may refuse this one or drop the other. Ask for a separate link.
- **Stuck at "connecting…" with "Flood control" in `csq-socks status`?** VK is limiting your IP. Close every other
  csqtt app (LaLune can leave clients running after you quit it: `sudo pkill -f '[c]lient-linux-x86_64'`), wait a few
  minutes, try again. `up` waits up to 4 minutes on its own (`WAIT=360 csq-socks up` for longer); don't Ctrl-C it.
- Something wrong in `tun` mode and `down` does not help: reboot — nothing csq-socks sets survives a restart.

## Windows

Download `csq-socks-windows.zip` from [Releases](https://github.com/SanityProtocol/csq-socks/releases), unpack it
anywhere (say `C:\csq-socks`), and run it from a terminal in that folder — nothing to install. The same commands and
settings as on Linux:

```powershell
.\csq-socks set      # paste your csqtt:// link (saved in the data folder next to csq-socks.exe)
.\csq-socks up       # SOCKS5 proxy on 127.0.0.1:1089 — no admin rights needed
.\csq-socks tun      # or: ALL traffic through the tunnel — from an admin terminal (Run as administrator)
.\csq-socks status
.\csq-socks down     # after tun: from an admin terminal too
```

- `up` changes nothing on the system, as on Linux: point a browser or app at `127.0.0.1:1089` (SOCKS v5, DNS through
  the proxy).
- Everything csq-socks keeps (link, settings, log) is in the `data` folder next to `csq-socks.exe`, and only you (and
  the system and administrators) can open the csq-socks folder. To remove it: `csq-socks down` (after `tun`, from an
  admin terminal), then delete the folder. Under `Program Files` the files go to `%LOCALAPPDATA%\csq-socks`.
- `tun` adds a network adapter named `csq-socks` and routes everything through it. Only the csqtt client's own VK
  traffic goes out directly. The kill switch blocks everything else
  (your local network stays reachable) if the tunnel drops, even if csq-socks itself is closed, until
  `csq-socks down` — or a restart. In `tun` every `-dns` form works, DoT and DoH included.
- Another network (Wi-Fi to cable, a new address): `tun` follows it on its own — traffic stays blocked for the few
  seconds it reconnects.
- Only an elevated client gets past the kill switch: a program that starts the client exe unelevated gets nothing.
- Not covered: traffic Windows forwards for others (WSL2, Hyper-V's Default Switch, Internet Connection Sharing)
  while csq-socks itself is not running — it is not this machine's own traffic, which the kill switch filters.
- `tun` uses Wintun (`wintun.dll`, unmodified, under its own licence: `LICENSE-wintun.txt`).

## Licence

The csq-socks scripts are MIT (`LICENSE`). The two csqtt clients in the release archives are amurcanov's, under the
PolyForm Noncommercial License — non-commercial use only (`NOTICE`, `LICENSE-csqtt`). They are not in git:
`release.sh` builds the archives from this repository plus the binaries, checked against `CLIENTS.sha256`.
