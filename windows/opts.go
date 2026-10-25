package main

// csq-socks set -mtu N -dns X -port N -streams N (-X default = back to the default, -reset = all of them), as link.py
// opts on Linux. Kept in settings.json beside conn.json, so a new link keeps them.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var optPath = filepath.Join(os.Getenv("APPDATA"), "csq-socks", "settings.json")

type settings struct {
	MTU     int    `json:"mtu,omitempty"`
	DNS     string `json:"dns,omitempty"`
	Port    int    `json:"port,omitempty"`
	Streams int    `json:"streams,omitempty"`
}

const dnsForms = "default, an IPv4 address (1.1.1.1 or 1.1.1.1,8.8.8.8), tls://IP[:PORT][#NAME] (DoT) or https://URL (DoH) — the tunnel carries IPv4 only"

func loadOpts() settings {
	var o settings
	if b, err := os.ReadFile(optPath); err == nil {
		json.Unmarshal(b, &o)
	}
	return o
}

// with the defaults filled in
func (o settings) eff() settings {
	if o.MTU == 0 {
		o.MTU = 1500
	}
	if o.DNS == "" {
		o.DNS = "default"
	}
	if o.Port == 0 {
		o.Port = 1089
	}
	if o.Streams == 0 {
		o.Streams = 10
	}
	return o
}

func (o settings) String() string {
	e := o.eff()
	return fmt.Sprintf("mtu %d · dns %s · port %d · streams %d", e.MTU, e.DNS, e.Port, e.Streams)
}

// dotAddr: tls://IP[:PORT][#NAME] → "IP:PORT", the name to verify (the IP when none)
func dotAddr(v string) (addr, name string, ok bool) {
	a, name, _ := strings.Cut(strings.TrimPrefix(v, "tls://"), "#")
	host, port := a, "853"
	if strings.HasPrefix(a, "[") {
		h, rest, _ := strings.Cut(a[1:], "]")
		host = h
		if p, found := strings.CutPrefix(rest, ":"); found {
			port = p
		}
	} else if strings.Count(a, ":") == 1 {
		host, port, _ = strings.Cut(a, ":")
	}
	ip, err := netip.ParseAddr(host)
	n, perr := strconv.Atoi(port)
	if err != nil || !ip.Is4() || perr != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	if name == "" {
		name = ip.String()
	}
	return netip.AddrPortFrom(ip, uint16(n)).String(), name, true
}

func checkDNS(v string) (string, error) {
	switch {
	case v == "default":
		return v, nil
	case strings.HasPrefix(v, "https://"):
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			if ip, err := netip.ParseAddr(u.Hostname()); err != nil || ip.Is4() {
				return v, nil
			}
		}
	case strings.HasPrefix(v, "tls://"):
		if _, _, ok := dotAddr(v); ok {
			return v, nil
		}
	default:
		var ips []string
		for _, a := range strings.Split(v, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(a))
			if err != nil || !ip.Is4() {
				return "", fmt.Errorf("-dns takes %s", dnsForms)
			}
			ips = append(ips, ip.String())
		}
		return strings.Join(ips, ","), nil
	}
	return "", fmt.Errorf("-dns takes %s", dnsForms)
}

func applyOpts(o settings, args []string) (settings, error) {
	ranges := map[string][2]int{"mtu": {576, 1500}, "port": {1, 65535}, "streams": {3, 100}} // streams: the client clamps -n to 3..100
	for i := 0; i < len(args); i++ {
		a := strings.TrimLeft(args[i], "-")
		if a == "reset" {
			o = settings{}
			continue
		}
		k, v, eq := strings.Cut(a, "=")
		if _, known := ranges[k]; !known && k != "dns" {
			return o, fmt.Errorf("unknown setting -%s — csq-socks set takes -mtu -dns -port -streams (or -reset)", k)
		}
		if !eq {
			if i+1 >= len(args) {
				return o, fmt.Errorf("-%s needs a value", k)
			}
			i++
			v = args[i]
		}
		if k == "dns" {
			if v == "default" {
				o.DNS = ""
			} else if d, err := checkDNS(v); err != nil {
				return o, err
			} else {
				o.DNS = d
			}
			continue
		}
		n := 0
		if v != "default" {
			r := ranges[k]
			var err error
			if n, err = strconv.Atoi(v); err != nil || n < r[0] || n > r[1] {
				return o, fmt.Errorf("-%s takes %d–%d (or default)", k, r[0], r[1])
			}
		}
		switch k {
		case "mtu":
			o.MTU = n
		case "port":
			o.Port = n
		case "streams":
			o.Streams = n
		}
	}
	return o, nil
}

func saveOpts(o settings) error {
	b, _ := json.Marshal(o)
	os.MkdirAll(filepath.Dir(optPath), 0o700)
	return os.WriteFile(optPath, append(b, '\n'), 0o600)
}
