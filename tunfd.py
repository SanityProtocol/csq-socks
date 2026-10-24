#!/usr/bin/env python3
# TUN-fd helper for csq-socks (from the csqtt sidecar kit). Opens /dev/net/tun (IFF_TUN|IFF_NO_PI), assigns the
# TUNCONF address, brings the device up, connects to the client's abstract UDS (--tun-uds) and hands it the
# fd via SCM_RIGHTS. Then it holds the fd open (the device would vanish if every fd closed) until killed.
#   usage: tunfd.py <uds_abstract_name> <tun_ifname> <addr/cidr> [extra_addr/32 ...]
import array, fcntl, os, socket, struct, subprocess, sys, time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

uds, ifname, addr = sys.argv[1], sys.argv[2], sys.argv[3]
extras = sys.argv[4:]

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack("16sH", ifname.encode(), IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

subprocess.check_call(["ip", "addr", "add", addr, "dev", ifname])
for e in extras:
    subprocess.check_call(["ip", "addr", "add", e, "dev", ifname])
subprocess.check_call(["ip", "link", "set", ifname, "up"])

# Connect to the client's abstract UDS listener and send the fd. Retry: the client may not have bound yet.
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
deadline = time.time() + 40
while True:
    try:
        s.connect("\0" + uds)
        break
    except (FileNotFoundError, ConnectionRefusedError, OSError):
        if time.time() > deadline:
            print("tunfd: could not connect to UDS", uds, file=sys.stderr)
            sys.exit(1)
        time.sleep(0.2)

s.sendmsg([b"\x01"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [tun]))])
try:
    ack = s.recv(1)
    print("tunfd: sent fd for", ifname, addr, "ack=", ack, flush=True)
except OSError:
    print("tunfd: sent fd (no ack read)", flush=True)

# Hold the fd open so the TUN device (and its addresses) persist for the client.
while True:
    time.sleep(3600)
