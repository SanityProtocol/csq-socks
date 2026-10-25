#!/bin/bash
# Build the release archive dist/csq-socks.tar.gz: this repository's files plus the two csqtt clients, which are not in
# git — put client-2.1.9 and client-2.5.2 next to this script; they must match CLIENTS.sha256.
set -eu
cd "$(dirname "$0")"
sha256sum -c --quiet CLIENTS.sha256 || { echo "the client binaries are missing or do not match CLIENTS.sha256"; exit 1; }
files=(csq-socks install.sh link.py socks5.py tunfd.py client-2.5.2 client-2.1.9 README.md LICENSE LICENSE-csqtt NOTICE
       VERSION CLIENTS.sha256 source/client-2.5.2.patch)
rm -rf dist; mkdir -p dist/csq-socks/source
for f in "${files[@]}"; do cp -p "$f" "dist/csq-socks/$f"; done
(cd dist/csq-socks && sha256sum "${files[@]}" > SHA256SUMS)
tar czf dist/csq-socks.tar.gz -C dist --owner=0 --group=0 --sort=name csq-socks
(cd dist && sha256sum csq-socks.tar.gz > csq-socks.tar.gz.sha256)
echo "csq-socks $(cat VERSION): dist/csq-socks.tar.gz"; cat dist/csq-socks.tar.gz.sha256
