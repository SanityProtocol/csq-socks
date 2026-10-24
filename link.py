#!/usr/bin/env python3
# csqtt link → connection JSON for csq-socks.
#   link.py parse      — read a csqtt:// link on stdin, print {line, host, port, password, hashes[]}
#   link.py get FIELD  — read that JSON on stdin, print one field (hashes comma-joined)
# Two link forms (swg-panel turn-artifacts.js csqttArtifact, the 2.5 server's encrypt_csqtt_link):
#   2.1: csqtt://connect?v=2&host=&peer=&password=&hashes=a+b   ('+' joins hashes, a literal '+' is %2B)
#   2.5: csqtt://<base64url(iv12 ‖ AES-256-GCM(payload) ‖ tag)>, key SHA-256("csqtt-chiper-key"), payload = the 2.1 query
import base64, hashlib, json, sys
from urllib.parse import unquote

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

if __name__ == "__main__":
    if sys.argv[1:] == ["parse"]:
        print(json.dumps(parse(sys.stdin.read())))
    elif len(sys.argv) == 3 and sys.argv[1] == "get":
        v = json.load(sys.stdin).get(sys.argv[2], "")
        print(",".join(v) if isinstance(v, list) else v)
    else:
        sys.exit("usage: link.py parse | link.py get FIELD")
