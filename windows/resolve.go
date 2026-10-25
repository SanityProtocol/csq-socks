package main

// DoT / DoH lookups for the proxy (csq-socks set -dns tls://… or https://…), inside the tunnel like everything else.
// One connection to the server, kept open and reused: a fresh TCP+TLS handshake through the tunnel per lookup took
// 1–7 s and a quarter of them stalled. Queries take turns on it; one the server closed meanwhile is retried once.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type resolver struct {
	spec string
	tnet *netstack.Net
	hc   *http.Client // DoH; its transport keeps the connection

	mu  sync.Mutex
	dot *tls.Conn

	cmu   sync.Mutex
	cache map[string]cached
}

type cached struct {
	ips []netip.Addr
	exp time.Time
}

func newResolver(spec string, tnet *netstack.Net) *resolver {
	r := &resolver{spec: spec, tnet: tnet, cache: map[string]cached{}}
	if strings.HasPrefix(spec, "https://") {
		r.hc = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			DialContext: tnet.DialContext, ForceAttemptHTTP2: true, IdleConnTimeout: 5 * time.Minute}}
	}
	return r
}

func dnsQuery(name string) []byte {
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1) // A, IN
}

func skipName(m []byte, i int) int {
	for i < len(m) && m[i] != 0 {
		if m[i]&0xC0 == 0xC0 {
			return i + 2
		}
		i += int(m[i]) + 1
	}
	return i + 1
}

func dnsAnswers(m []byte) (ips []netip.Addr, ttl uint32) {
	if len(m) < 12 || m[3]&0x0F != 0 {
		return nil, 0
	}
	qd, an := binary.BigEndian.Uint16(m[4:]), binary.BigEndian.Uint16(m[6:])
	i := 12
	for ; qd > 0; qd-- {
		i = skipName(m, i) + 4
	}
	ttl = 300
	for ; an > 0; an-- {
		i = skipName(m, i)
		if i+10 > len(m) {
			break
		}
		t, tt, n := binary.BigEndian.Uint16(m[i:]), binary.BigEndian.Uint32(m[i+4:]), int(binary.BigEndian.Uint16(m[i+8:]))
		if i+10+n > len(m) {
			break
		}
		if t == 1 && n == 4 {
			ips = append(ips, netip.AddrFrom4([4]byte(m[i+10:i+14])))
			ttl = min(ttl, tt)
		}
		i += 10 + n
	}
	return ips, ttl
}

func (r *resolver) dotOpen() (*tls.Conn, error) {
	addr, name, _ := dotAddr(r.spec)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := r.tnet.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{ServerName: name})
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func (r *resolver) ask(q []byte) ([]byte, error) {
	if r.hc != nil {
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			var resp *http.Response
			req, _ := http.NewRequest("POST", r.spec, bytes.NewReader(q))
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("Accept", "application/dns-message")
			if resp, err = r.hc.Do(req); err == nil {
				m, rerr := io.ReadAll(io.LimitReader(resp.Body, 65535))
				resp.Body.Close()
				if resp.StatusCode == 200 && rerr == nil {
					return m, nil
				}
				err = fmt.Errorf("DoH answered HTTP %d", resp.StatusCode)
			}
		}
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if r.dot == nil {
			if r.dot, err = r.dotOpen(); err != nil {
				continue
			}
		}
		r.dot.SetDeadline(time.Now().Add(10 * time.Second))
		var m []byte
		if _, err = r.dot.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err == nil {
			var l [2]byte
			if _, err = io.ReadFull(r.dot, l[:]); err == nil {
				m = make([]byte, binary.BigEndian.Uint16(l[:]))
				_, err = io.ReadFull(r.dot, m)
			}
		}
		if err == nil {
			return m, nil
		}
		r.dot.Close()
		r.dot = nil
	}
	return nil, err
}

// warm: the first handshake through the tunnel is the slow one: have it done before the first lookup
func (r *resolver) warm() {
	if r.hc != nil {
		if u, err := http.NewRequest("HEAD", r.spec, nil); err == nil {
			if resp, err := r.hc.Do(u); err == nil {
				resp.Body.Close()
			}
		}
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dot == nil {
		r.dot, _ = r.dotOpen()
	}
}

func (r *resolver) lookup(name string) ([]netip.Addr, error) {
	r.cmu.Lock()
	c, hit := r.cache[name]
	r.cmu.Unlock()
	if hit && time.Now().Before(c.exp) {
		return c.ips, nil
	}
	m, err := r.ask(dnsQuery(name))
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: name}
	}
	ips, ttl := dnsAnswers(m)
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no A record", Name: name, IsNotFound: true}
	}
	r.cmu.Lock()
	r.cache[name] = cached{ips, time.Now().Add(time.Duration(max(30, min(ttl, 300))) * time.Second)}
	r.cmu.Unlock()
	return ips, nil
}

// dial: names through the resolver, each address in turn
func (r *resolver) dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ips := []netip.Addr{}
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, ip)
	} else if ips, err = r.lookup(host); err != nil {
		return nil, err
	}
	err := errors.New("no address")
	for _, ip := range ips {
		var c net.Conn
		if c, err = r.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}
