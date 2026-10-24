#!/bin/bash
# csq-socks installer: copies this folder (the unpacked release archive) to /opt/csq-socks and puts csq-socks on the PATH.
#   sudo ./install.sh             install, or update in place
#   sudo ./install.sh uninstall   disconnect and remove everything it installed
set -eu
SRC=$(cd "$(dirname "$0")" && pwd); DST=/opt/csq-socks
[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"

if [ "${1:-}" = uninstall ]; then
  [ -x $DST/csq-socks ] && $DST/csq-socks down >/dev/null 2>&1 || true
  rm -rf $DST /usr/local/lib/csq-socks /run/csq-socks; rm -f /usr/local/bin/csq-socks
  id csqs >/dev/null 2>&1 && userdel csqs || true
  echo "csq-socks removed (a saved link stays in ~/.config/csq-socks of the user who saved it)"; exit 0
fi

[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo "csq-socks needs Linux on x86_64"; exit 1; }
g=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
[ -n "$g" ] && [ "$(printf '%s\n2.34\n' "$g" | sort -V | head -1)" = 2.34 ] \
  || { echo "csq-socks needs glibc 2.34 or newer (Ubuntu 22.04+, Debian 12+); this system has ${g:-none}"; exit 1; }
(cd "$SRC" && sha256sum -c --quiet SHA256SUMS) || { echo "a file does not match SHA256SUMS — download the archive again"; exit 1; }
need(){ miss=""; for t in python3 ip ss setpriv curl useradd; do command -v $t >/dev/null || miss="$miss $t"; done
  python3 -c 'import cryptography' 2>/dev/null || miss="$miss python3-cryptography"; }   # only a 2.5 (sealed) link needs it
need
if [ -n "$miss" ] && command -v apt-get >/dev/null; then
  echo "installing:$miss"
  { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-cryptography iproute2 util-linux curl passwd; } >/dev/null 2>&1 || true
  need
fi
case "$miss" in "" | " python3-cryptography") ;; *) echo "missing:$miss — install python3 iproute2 util-linux curl and retry"; exit 1;; esac
[ -z "$miss" ] || echo "note: python3-cryptography is missing (pip or your package manager) — 2.1 links work, 2.5 links need it"

install -d -m 755 $DST $DST/source
install -m 755 "$SRC"/install.sh "$SRC"/csq-socks "$SRC"/link.py "$SRC"/socks5.py "$SRC"/tunfd.py "$SRC"/client-2.5.1 "$SRC"/client-2.1.9 $DST/
install -m 644 "$SRC"/README.md "$SRC"/LICENSE "$SRC"/LICENSE-csqtt "$SRC"/NOTICE "$SRC"/VERSION "$SRC"/CLIENTS.sha256 "$SRC"/SHA256SUMS $DST/
install -m 644 "$SRC"/source/* $DST/source/
ln -sf $DST/csq-socks /usr/local/bin/csq-socks
echo "csq-socks $(cat "$SRC/VERSION") installed in $DST"
echo "next:  csq-socks set   (paste your csqtt:// link)"
echo "then:  csq-socks up    (SOCKS5 on 127.0.0.1:1089)   or   csq-socks tun   (all traffic through the tunnel)"
