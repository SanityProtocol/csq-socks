# csq-socks

Connect a Linux laptop or server to a **csqtt** server (2.1 or 2.5) from the command line: paste the `csqtt://` link
you were given, and use the tunnel either as a **SOCKS5 proxy** or as a **full tunnel** for all traffic.

Linux x86_64, glibc 2.34+ (Ubuntu 22.04+, Debian 12+), root (sudo). Needs access to VK: csqtt gets its relays
through VK calls.

## Install

```bash
curl -fsSL https://github.com/SanityProtocol/csq-socks/releases/latest/download/csq-socks.tar.gz | tar xz -C /tmp && sudo /tmp/csq-socks/install.sh
```

The same command updates an installed copy. Without internet on that machine: download `csq-socks.tar.gz` from
[Releases](https://github.com/SanityProtocol/csq-socks/releases), copy it over, then
`tar xzf csq-socks.tar.gz && sudo csq-socks/install.sh`.

Remove: `sudo /opt/csq-socks/install.sh uninstall`.

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
```

| setting | default | |
|---|---|---|
| `-mtu` | 1500 | 576–1500: the tunnel's packet size. Lower it if pages stall while small requests work. |
| `-dns` | `default` | `up`: the server's DNS; `tun`: your system's DNS, through the tunnel. Or an IP (`1.1.1.1`, `1.1.1.1,8.8.8.8`), DoT `tls://IP[#name]`, or DoH `https://…` (`up` only). In `tun`, a DNS setting needs systemd-resolved (Ubuntu, most desktops). |
| `-port` | 1089 | the proxy's port (`csq-socks up 1095` still picks one for a single run) |
| `-streams` | 10 | 3–100 parallel csqtt streams |

The settings stay in `~/.config/csq-socks/settings.json`; a new link keeps them. `csq-socks status` shows them.

## Good to know

- **The link picks the client.** A readable `csqtt://connect?…` link is a 2.1 server; a long scrambled `csqtt://…`
  link is a 2.5 server. A 2.1 link only works with a 2.1 server, a 2.5 link only with a 2.5 server.
- **A 2.1 link is tied to one device.** If the same link is already used in an app (LaLune, FOCSQ, the phone app),
  a 2.1 server may refuse this one or drop the other. Ask for a separate link.
- **Stuck at "connecting…" with "Flood control" in `csq-socks status`?** VK is limiting your IP. Close every other
  csqtt app (LaLune can leave clients running after you quit it: `sudo pkill -f '[c]lient-linux-x86_64'`), wait a few
  minutes, try again. `up` waits up to 4 minutes on its own (`WAIT=360 csq-socks up` for longer); don't Ctrl-C it.
- Something wrong in `tun` mode and `down` does not help: reboot — nothing csq-socks sets survives a restart.

## Licence

The csq-socks scripts are MIT (`LICENSE`). The two csqtt clients in the release archive are amurcanov's, under the
PolyForm Noncommercial License — non-commercial use only (`NOTICE`, `LICENSE-csqtt`). They are not in git:
`release.sh` builds the archive from this repository plus the two binaries, checked against `CLIENTS.sha256`.

---

## По-русски

Подключение Linux к серверу **csqtt** (2.1 или 2.5) из командной строки: вставьте полученную ссылку `csqtt://`
и пользуйтесь туннелем как **SOCKS5-прокси** или как **полным туннелем** для всего трафика.

Установка (и обновление):

```bash
curl -fsSL https://github.com/SanityProtocol/csq-socks/releases/latest/download/csq-socks.tar.gz | tar xz -C /tmp && sudo /tmp/csq-socks/install.sh
```

Удаление: `sudo /opt/csq-socks/install.sh uninstall`

```bash
csq-socks set      # вставить ссылку csqtt:// и нажать Enter
csq-socks up       # SOCKS5-прокси на 127.0.0.1:1089
csq-socks tun      # или: весь трафик через туннель
csq-socks status   # состояние, внешний IP, последние строки лога
csq-socks down     # отключиться
```

- В режиме `up` система не меняется: через туннель идёт только то, что направлено на `127.0.0.1:1089`
  (в Firefox — SOCKS v5 и «Отправлять DNS-запросы через прокси»).
- В режиме `tun` весь трафик и DNS идут через csqtt; при обрыве туннеля трафик **блокируется** до `csq-socks down`.
  Другие VPN на это время выключите.
- Настройки: `csq-socks set -mtu 1400 -dns tls://9.9.9.9#dns.quad9.net` (ссылка уже сохранена — меняются только
  настройки), `-port`, `-streams`; `-X default` возвращает одну, `-reset` — все. DNS: IP, DoT `tls://IP[#имя]`
  или DoH `https://…` (только `up`); в режиме `tun` DNS-настройка требует systemd-resolved. Показывает `csq-socks status`.
- Ссылка 2.1 привязана к одному устройству: если она уже используется в другом приложении, попросите отдельную.
- Зависло на «connecting…», а в `csq-socks status` — «Flood control»: VK ограничил ваш IP. Закройте другие клиенты
  csqtt, подождите несколько минут и повторите; не прерывайте `up` через Ctrl-C.
