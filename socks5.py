#!/usr/bin/env python3
# Minimal SOCKS5 (no auth, CONNECT only) for csq-socks. The listening socket is inherited as fd $CSQS_FD, created
# in the host namespace on 127.0.0.1; this process runs inside the csqs netns, so every outbound connect and every
# name lookup (socks5h) goes through the csqtt tunnel. stdlib only.
# $CSQS_DNS (from csq-socks set -dns): tls://IP[:PORT][#NAME] or https://URL — names are then looked up there, by DoT or
# DoH (inside the tunnel too); otherwise by the netns resolv.conf. A DoH URL's own host resolves by resolv.conf.
import http.client, os, socket, ssl, struct, sys, threading, time
from urllib.parse import urlsplit

DNS = os.environ.get("CSQS_DNS", "")
cache, cache_lock = {}, threading.Lock()

def dns_query(name):
    q = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode("idna")
    return q + b"\x00" + struct.pack("!HH", 1, 1)   # A, IN

def skip_name(m, i):
    while m[i]:
        if m[i] & 0xC0 == 0xC0:
            return i + 2
        i += m[i] + 1
    return i + 1

def dns_answers(m):
    qd, an = struct.unpack("!HH", m[4:8])
    if m[3] & 0x0F:
        return [], 0
    i = 12
    for _ in range(qd):
        i = skip_name(m, i) + 4
    ips, ttl = [], 300
    for _ in range(an):
        i = skip_name(m, i)
        t, _, tt, n = struct.unpack("!HHIH", m[i:i + 10])
        if t == 1 and n == 4:
            ips.append(socket.inet_ntoa(m[i + 10:i + 14])); ttl = min(ttl, tt)
        i += 10 + n
    return ips, ttl

# One connection to the DoT/DoH server, kept open and reused: a fresh TCP+TLS handshake through the tunnel per lookup
# took 1–7 s and a quarter of them stalled. Queries take turns on it; one the server closed meanwhile is retried once.
upstream, upstream_lock = None, threading.Lock()

def dot_open():
    addr, _, sni = DNS[len("tls://"):].partition("#")
    host, port = addr, 853
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else port
    elif addr.count(":") == 1:
        host, port = addr.split(":")[0], int(addr.split(":")[1])
    raw = socket.create_connection((host, port), timeout=10)
    try:
        return ssl.create_default_context().wrap_socket(raw, server_hostname=sni or host)
    except BaseException:
        raw.close(); raise

def doh_open():
    u = urlsplit(DNS)
    return http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=10, context=ssl.create_default_context())

def ask(q):
    global upstream
    with upstream_lock:
        for attempt in (0, 1):
            try:
                if DNS.startswith("https://"):
                    upstream = upstream or doh_open()
                    u = urlsplit(DNS)
                    upstream.request("POST", (u.path or "/") + ("?" + u.query if u.query else ""), body=q,
                                     headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
                    r = upstream.getresponse(); m = r.read()
                    if r.status != 200:
                        raise OSError("DoH answered HTTP %d" % r.status)
                else:
                    upstream = upstream or dot_open()
                    upstream.sendall(struct.pack("!H", len(q)) + q)
                    m = recvn(upstream, struct.unpack("!H", recvn(upstream, 2))[0])
                return m
            except (OSError, ConnectionError, http.client.HTTPException, struct.error):
                if upstream:
                    try: upstream.close()
                    except OSError: pass
                upstream = None
                if attempt:
                    raise

def warm():   # the first handshake through the tunnel is the slow one: have it done before the first lookup
    global upstream
    with upstream_lock:
        try:
            if DNS.startswith("https://"):
                upstream = doh_open(); upstream.connect()
            else:
                upstream = dot_open()
        except OSError:
            upstream = None

def lookup(name):
    with cache_lock:
        hit = cache.get(name)
    if hit and hit[1] > time.monotonic():
        return hit[0]
    ips, ttl = dns_answers(ask(dns_query(name)))
    if not ips:
        raise socket.gaierror("no A record for " + name)
    with cache_lock:
        cache[name] = (ips, time.monotonic() + max(30, min(ttl, 300)))
    return ips

def connect(host, port):
    if not DNS:
        return socket.create_connection((host, port), timeout=20)
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        ips = [host]
    except OSError:
        try:
            ips = lookup(host)
        except (OSError, ValueError, IndexError, struct.error, UnicodeError) as e:
            raise socket.gaierror(str(e))
    err = None
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout=20)
        except OSError as e:
            err = e
    raise err

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("eof")
        b += c
    return b

def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for s, how in ((b, socket.SHUT_WR), (a, socket.SHUT_RD)):
        try:
            s.shutdown(how)
        except OSError:
            pass

def reply(c, code):
    c.sendall(b"\x05" + bytes([code]) + b"\x00\x01" + b"\x00" * 6)

def handle(c):
    up = None
    try:
        ver, n = recvn(c, 2)
        if ver != 5:
            return
        if 0 not in recvn(c, n):
            c.sendall(b"\x05\xff"); return
        c.sendall(b"\x05\x00")
        ver, cmd, _, atyp = recvn(c, 4)
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, recvn(c, 4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recvn(c, 16))
        elif atyp == 3:
            host = recvn(c, recvn(c, 1)[0]).decode("idna")
        else:
            reply(c, 8); return
        port = struct.unpack("!H", recvn(c, 2))[0]
        if cmd != 1:
            reply(c, 7); return
        try:
            up = connect(host, port)
            up.settimeout(None)
        except socket.gaierror:
            reply(c, 4); return
        except ConnectionRefusedError:
            reply(c, 5); return
        except OSError:
            reply(c, 1); return
        reply(c, 0)
        t = threading.Thread(target=pump, args=(up, c), daemon=True); t.start()
        pump(c, up); t.join()
    except (OSError, ConnectionError, ValueError, UnicodeError):
        pass
    finally:
        for s in (c, up):
            if s:
                try: s.close()
                except OSError: pass

def main():
    ls = socket.socket(fileno=int(os.environ["CSQS_FD"]))
    print("socks5: serving on %s:%d" % ls.getsockname()[:2], flush=True)
    if DNS:
        threading.Thread(target=warm, daemon=True).start()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    sys.exit(main())
