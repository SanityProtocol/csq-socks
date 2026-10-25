package main

// csq-socks tun: ALL traffic through csqtt. A Wintun adapter "csq-socks" carries 0.0.0.0/1 + 128.0.0.0/1 (ahead of
// any default route), and its packets go to and from the client's UDP port. The client itself binds every socket to
// the physical network's address (--bind-ip): Windows sends a bound socket out of the interface that owns the address,
// past the tunnel's routes — the uid rule of tun on Linux. The kill switch is Windows Filtering Platform filters
// (firewall/): everything but the tunnel, the client's exe, loopback, DHCP and the LAN is blocked, and the filters
// stay until csq-socks down or a reboot, whatever happens to this process. -dns: an IP goes on the adapter; DoT/DoH
// go through a forwarder on 127.0.0.1:53 here; with any DNS setting nothing else reaches a DNS server.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"csq-socks/firewall"
)

const adapter = "csq-socks"

type physical struct {
	ip    netip.Addr
	alias string
}

func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// physicalNet: the interface of the default route with the lowest metric (ours excluded) and its IPv4 address
func physicalNet() (physical, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return physical{}, err
	}
	var best *winipcfg.MibIPforwardRow2
	bestMetric := ^uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		iface, err := r.InterfaceLUID.Interface()
		if err != nil || iface.Alias() == adapter {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil || !ipif.Connected {
			continue
		}
		if m := r.Metric + ipif.Metric; m < bestMetric {
			best, bestMetric = r, m
		}
	}
	if best == nil {
		return physical{}, errors.New("no default route — is the network connected?")
	}
	addrs, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return physical{}, err
	}
	iface, _ := best.InterfaceLUID.Interface()
	for _, a := range addrs {
		if a.InterfaceLUID == best.InterfaceLUID && !a.Address.Addr().IsLinkLocalUnicast() {
			return physical{ip: a.Address.Addr(), alias: iface.Alias()}, nil
		}
	}
	return physical{}, fmt.Errorf("the default route's interface %s has no IPv4 address", iface.Alias())
}

// installClient: the client runs from %ProgramFiles%\csq-socks, which only admins can write — the kill switch lets
// that exe through, so it must not be one anybody can replace (on Linux: /usr/local/lib/csq-socks)
func installClient(name string) (string, error) {
	src := filepath.Join(exeDir, name)
	dir := filepath.Join(os.Getenv("ProgramFiles"), "csq-socks")
	dst := filepath.Join(dir, name)
	want, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if have, err := os.ReadFile(dst); err == nil && sha256.Sum256(have) == sha256.Sum256(want) {
		return dst, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, want, 0o755); err != nil {
		return "", err
	}
	return dst, os.Rename(tmp, dst)
}

func tunRun(st *state, fail func(string) error, cl *clientRun, clientPath string, cport int, tip netip.Addr,
	serverDNS []string, o settings, ph physical) error {
	mtu := envInt("MTU", o.MTU)
	dev, err := tun.CreateTUN(adapter, mtu)
	if err != nil {
		return fail("the tunnel adapter (wintun.dll next to csq-socks.exe?): " + err.Error())
	}
	cleanup := func(why string) error {
		firewall.Disable()
		dev.Close()
		return fail(why)
	}
	luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(tip, 32)}); err != nil {
		return cleanup("tunnel address: " + err.Error())
	}
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.NLMTU, ipif.UseAutomaticMetric, ipif.Metric = uint32(mtu), false, 1 // metric 1: its DNS is asked first
		ipif.Set()
	}
	for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := luid.AddRoute(netip.MustParsePrefix(r), netip.IPv4Unspecified(), 0); err != nil {
			return cleanup("route " + r + ": " + err.Error())
		}
	}

	// the pump first: the DoH host lookup below already goes through the tunnel
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cport})
	if err != nil {
		return cleanup("client port: " + err.Error())
	}
	uc.SetReadBuffer(4 << 20)
	uc.SetWriteBuffer(4 << 20)
	go func() { // adapter → client
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				continue
			}
			for i := 0; i < n; i++ {
				uc.Write(bufs[i][:sizes[i]])
			}
		}
	}()
	go func() { // client → adapter
		buf := make([]byte, 65535)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				time.Sleep(50 * time.Millisecond) // ICMP port unreachable before the client listens
				continue
			}
			dev.Write([][]byte{buf[:n]}, 0)
		}
	}()

	spec := env("DNS", o.DNS)
	var allowDNS []netip.Addr
	switch {
	case spec == "default": // the system's DNS, now through the tunnel (or the LAN)
	case strings.HasPrefix(spec, "tls://") || strings.HasPrefix(spec, "https://"):
		// the forwarder's own connection goes out like any program's: through the tunnel. A DoH URL's host is
		// looked up once here, at the server's DNS, before the kill switch — then only the forwarder is a DNS server
		dialTCP := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
		if u, err := url.Parse(spec); err == nil && strings.HasPrefix(spec, "https://") {
			if _, err := netip.ParseAddr(u.Hostname()); err != nil {
				bootstrap := strings.TrimSpace(serverDNS[0])
				res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(bootstrap, "53"))
				}}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				ips, err := res.LookupNetIP(ctx, "ip4", u.Hostname())
				cancel()
				if err != nil || len(ips) == 0 {
					return cleanup(fmt.Sprintf("could not look up %s at %s: %v", u.Hostname(), bootstrap, err))
				}
				pin := ips[0].String()
				dial := dialTCP
				dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
					_, port, _ := net.SplitHostPort(addr)
					return dial(ctx, network, net.JoinHostPort(pin, port))
				}
			}
		}
		pc, err := net.ListenPacket("udp", "127.0.0.1:53")
		if err != nil {
			return cleanup("the DNS forwarder needs 127.0.0.1:53, which is taken: " + err.Error())
		}
		r := newResolver(spec, dialTCP)
		go r.serveDNS(pc)
		go r.warm()
		loop := netip.MustParseAddr("127.0.0.1")
		if err := luid.SetDNS(windows.AF_INET, []netip.Addr{loop}, nil); err != nil {
			return cleanup("adapter DNS: " + err.Error())
		}
		allowDNS = []netip.Addr{loop}
	default:
		for _, d := range strings.Split(spec, ",") {
			if a, err := netip.ParseAddr(d); err == nil {
				allowDNS = append(allowDNS, a)
			}
		}
		if err := luid.SetDNS(windows.AF_INET, allowDNS, nil); err != nil {
			return cleanup("adapter DNS: " + err.Error())
		}
	}
	if err := firewall.Enable(uint64(luid), clientPath, allowDNS); err != nil {
		return cleanup("kill switch: " + err.Error())
	}

	st.Phase, st.TIP, st.DNS = "up", tip.String(), []string{spec}
	st.Phys = ph.alias + " " + ph.ip.String()
	writeState(*st)
	<-cl.exited
	// the adapter stays and the filters stay: traffic is blocked, not leaked, until csq-socks down
	st.Phase, st.Detail = "blocked", "the client exited — traffic is blocked until csq-socks down"
	writeState(*st)
	select {}
}

// exitIPDirect: the exit as any program sees it (tun routes everything)
func exitIPDirect() string {
	req, _ := http.NewRequest("GET", "https://ifconfig.me", nil)
	req.Header.Set("User-Agent", "curl/8")
	r, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "(no answer yet)"
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 256))
	return string(bytes.TrimSpace(b))
}

// tunDNSCheck: what tun can do with the DNS setting — everything up can
func tunDNSCheck(spec string) error {
	_, err := checkDNS(spec)
	return err
}
