package main

// Minimal SOCKS5 (no auth, CONNECT only), as socks5.py on Linux. Every outbound connect and every name lookup
// (socks5h) goes through the userspace stack, so through the csqtt tunnel; nothing else on the machine does.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

type dialer func(ctx context.Context, host string, port uint16) (net.Conn, error)

func serveSocks(ls net.Listener, dial dialer) {
	for {
		c, err := ls.Accept()
		if err != nil {
			return
		}
		go handleSocks(c, dial)
	}
}

func reply(c net.Conn, code byte) {
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func handleSocks(c net.Conn, dial dialer) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil || b[0] != 5 {
		return
	}
	n := int(b[1])
	if _, err := io.ReadFull(c, b[:n]); err != nil {
		return
	}
	if !strings.ContainsRune(string(b[:n]), 0) {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return
	}
	cmd, atyp := b[1], b[3]
	var host string
	switch atyp {
	case 1, 4:
		l := map[byte]int{1: 4, 4: 16}[atyp]
		if _, err := io.ReadFull(c, b[:l]); err != nil {
			return
		}
		host = net.IP(b[:l]).String()
	case 3:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return
		}
		l := int(b[0])
		if _, err := io.ReadFull(c, b[:l]); err != nil {
			return
		}
		host = string(b[:l])
	default:
		reply(c, 8)
		return
	}
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(b[:2])
	if cmd != 1 {
		reply(c, 7)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	up, err := dial(ctx, host, port)
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		switch {
		case errors.As(err, &dnsErr):
			reply(c, 4)
		case strings.Contains(err.Error(), "refused"):
			reply(c, 5)
		default:
			reply(c, 1)
		}
		return
	}
	defer up.Close()
	reply(c, 0)
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		io.Copy(up, c)
		closeWrite(up)
		close(done)
	}()
	io.Copy(c, up)
	closeWrite(c)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
