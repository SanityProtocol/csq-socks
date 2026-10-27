#!/bin/bash
# Build the release archives: dist/csq-socks.tar.gz (Linux) and dist/csq-socks-windows.zip, this repository's files
# plus what is not in git — client-2.1.9, client-2.5.3, client-2.1.9.exe, client-2.5.3.exe and wintun.dll next to this
# script, matching CLIENTS.sha256 — and windows/csq-socks.exe, built here (Go in docker).
set -eu
cd "$(dirname "$0")"
sha256sum -c --quiet CLIENTS.sha256 || { echo "the client binaries are missing or do not match CLIENTS.sha256"; exit 1; }
files=(csq-socks install.sh link.py socks5.py tunfd.py client-2.5.3 client-2.1.9 README.md README.en.md LICENSE LICENSE-csqtt NOTICE
       VERSION CLIENTS.sha256 source/client-2.5.3.patch)
rm -rf dist; mkdir -p dist/csq-socks/source
for f in "${files[@]}"; do cp -p "$f" "dist/csq-socks/$f"; done
(cd dist/csq-socks && sha256sum "${files[@]}" > SHA256SUMS)
tar czf dist/csq-socks.tar.gz -C dist --owner=0 --group=0 --sort=name csq-socks
docker run --rm -v "$PWD/windows:/w" -v "$HOME/.cache/csq-socks-go:/gomod" -e GOMODCACHE=/gomod -e GOPATH=/tmp/gopath \
  -e GOCACHE=/gomod/.buildcache -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 -w /w -u "$(id -u):$(id -g)" -e HOME=/tmp \
  golang:1.27.1-bookworm go build -trimpath -ldflags="-s -w" -o csq-socks.exe .
grep -q "const version = \"$(cat VERSION)\"" windows/main.go || { echo "windows/main.go's version is not $(cat VERSION)"; exit 1; }
win=(windows/csq-socks.exe client-2.5.3.exe client-2.1.9.exe wintun.dll README.md README.en.md LICENSE LICENSE-csqtt LICENSE-wintun.txt
     NOTICE VERSION CLIENTS.sha256 source/client-2.5.3.patch source/client-2.5.3-windows-bind-ip.patch
     source/client-2.1.9-windows-bind-ip.patch)
mkdir -p dist/csq-socks-windows/source
for f in "${win[@]}"; do cp -p "$f" "dist/csq-socks-windows/${f#windows/}"; done
(cd dist/csq-socks-windows && sha256sum $(printf '%s\n' "${win[@]}" | sed 's|^windows/||') > SHA256SUMS)
(cd dist && rm -f csq-socks-windows.zip && python3 -I -c 'import os, sys, zipfile
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
for d, _, fs in sorted(os.walk("csq-socks-windows")):
    for f in sorted(fs): z.write(os.path.join(d, f))' csq-socks-windows.zip)
(cd dist && sha256sum csq-socks.tar.gz > csq-socks.tar.gz.sha256 && sha256sum csq-socks-windows.zip > csq-socks-windows.zip.sha256)
echo "csq-socks $(cat VERSION): dist/csq-socks.tar.gz, dist/csq-socks-windows.zip"; cat dist/*.sha256
