#!/usr/bin/env python3
# csqtt link → connection JSON for csq-socks.
#   link.py parse      — read a csqtt:// link on stdin, print {line, host, port, password, hashes[]}
#   link.py get FIELD  — read that JSON on stdin, print one field (hashes comma-joined)
#   link.py opts FLAG… — read the settings JSON on stdin (may be empty), apply `csq-socks set` flags, print the result
#   link.py opt NAME   — read the settings JSON on stdin, print that setting (its default when unset); `opt all` = one line
# Two link forms (swg-panel turn-artifacts.js csqttArtifact, the 2.5 server's encrypt_csqtt_link):
#   2.1: csqtt://connect?v=2&host=&peer=&password=&hashes=a+b   ('+' joins hashes, a literal '+' is %2B)
#   2.5: csqtt://<base64url(iv12 ‖ AES-256-GCM(payload) ‖ tag)>, key SHA-256("csqtt-chiper-key"), payload = the 2.1 query
import base64, hashlib, ipaddress, json, sys
from urllib.parse import unquote, urlsplit

SEED = b"csqtt-chiper-key"   # sic — the csqtt authors' spelling

def unseal(blob):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        sys.exit("a 2.5 (sealed) link needs python3-cryptography: sudo apt install python3-cryptography")
    raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
    try:
        return AESGCM(hashlib.sha256(SEED).digest()).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        sys.exit("not a csqtt link: the sealed payload does not decrypt")

def parse(link):
    link = "".join(link.split())
    if not link.startswith("csqtt://"):
        sys.exit("expected a csqtt:// link")
    body, line = link[len("csqtt://"):], "2.1"
    if not body.startswith("connect?"):
        body, line = unseal(body), "2.5"
    q = {}
    for kv in body.split("?", 1)[-1].split("&"):
        k, _, v = kv.partition("=")
        q[k] = v
    hashes = [unquote(h) for h in q.get("hashes", "").split("+") if h]
    c = {"line": line, "host": unquote(q.get("host", "")).strip("[]"), "port": q.get("peer", ""),
         "password": unquote(q.get("password", "")), "hashes": hashes}
    if not c["host"] or not c["port"].isdigit():
        sys.exit("the link has no host or port")
    if not c["password"]:
        sys.exit("the link has no password")
    if not hashes:
        sys.exit("the link carries no VK call hashes — add a VK call link to this user in the panel first")
    return c

# csq-socks set -mtu N -dns X -port N -streams N (-X default = back to the default, -reset = all of them)
DEFAULTS = {"mtu": 1500, "dns": "default", "port": 1089, "streams": 10}
RANGES = {"mtu": (576, 1500), "port": (1, 65535), "streams": (3, 100)}   # streams: the client clamps -n to 3..100
DNS_FORMS = "default, an IP (1.1.1.1 or 1.1.1.1,8.8.8.8), tls://IP[:PORT][#NAME] (DoT) or https://URL (DoH)"

def check_dns(v):
    if v == "default":
        return v
    if v.startswith("https://"):
        if urlsplit(v).hostname:
            return v
    elif v.startswith("tls://"):
        addr = v[len("tls://"):].partition("#")[0]
        host, port = addr, "853"
        if addr.startswith("["):
            host, _, rest = addr[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else port
        elif addr.count(":") == 1:
            host, port = addr.split(":")
        try:
            ipaddress.ip_address(host)
            if port.isdigit() and 0 < int(port) < 65536:
                return v
        except ValueError:
            pass
    else:
        try:
            return ",".join(str(ipaddress.ip_address(a.strip())) for a in v.split(","))
        except ValueError:
            pass
    sys.exit("-dns takes " + DNS_FORMS)

def opts(cur, args):
    i = 0
    while i < len(args):
        a = args[i].lstrip("-")
        if a == "reset":
            cur = {}; i += 1; continue
        k, eq, v = a.partition("=")
        if k not in DEFAULTS:
            sys.exit("unknown setting -%s — csq-socks set takes -mtu -dns -port -streams (or -reset)" % k)
        if not eq:
            if i + 1 >= len(args):
                sys.exit("-%s needs a value" % k)
            i += 1; v = args[i]
        i += 1
        if v == "default":
            cur.pop(k, None)
        elif k == "dns":
            cur[k] = check_dns(v)
        else:
            lo, hi = RANGES[k]
            if not v.isdigit() or not lo <= int(v) <= hi:
                sys.exit("-%s takes %d–%d (or default)" % (k, lo, hi))
            cur[k] = int(v)
    return cur

def load(f):
    t = f.read().strip()
    return json.loads(t) if t else {}

if __name__ == "__main__":
    if sys.argv[1:2] == ["opts"]:
        print(json.dumps(opts(load(sys.stdin), sys.argv[2:])))
    elif len(sys.argv) == 3 and sys.argv[1] == "opt":
        o = {**DEFAULTS, **load(sys.stdin)}
        print(" · ".join("%s %s" % kv for kv in o.items()) if sys.argv[2] == "all" else o[sys.argv[2]])
    elif sys.argv[1:] == ["parse"]:
        print(json.dumps(parse(sys.stdin.read())))
    elif len(sys.argv) == 3 and sys.argv[1] == "get":
        v = json.load(sys.stdin).get(sys.argv[2], "")
        print(",".join(v) if isinstance(v, list) else v)
    else:
        sys.exit("usage: link.py parse | link.py get FIELD | link.py opts FLAG… | link.py opt NAME")
