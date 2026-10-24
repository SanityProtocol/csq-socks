#!/usr/bin/env python3
# Minimal SOCKS5 (no auth, CONNECT only) for csq-socks. The listening socket is inherited as fd $CSQS_FD, created
# in the host namespace on 127.0.0.1; this process runs inside the csqs netns, so every outbound connect and every
# name lookup (socks5h) goes through the csqtt tunnel. stdlib only.
import os, socket, struct, sys, threading

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
            up = socket.create_connection((host, port), timeout=20)
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
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    sys.exit(main())
