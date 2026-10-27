package main

// csq-socks tun: ALL traffic through csqtt. A Wintun adapter "csq-socks" carries 0.0.0.0/1 + 128.0.0.0/1 (ahead of
// any default route), and its packets go to and from the client's UDP port. The client itself binds every socket to
// the physical network's address (--bind-ip): Windows sends a bound socket out of the interface that owns the address,
// past the tunnel's routes — the uid rule of tun on Linux. The kill switch is Windows Filtering Platform filters
// (firewall/): everything but the tunnel, the client's exe (from the csq-socks folder, and only run elevated), loopback,
// DHCP and the LAN is blocked, and the filters
// stay until csq-socks down or a reboot, whatever happens to this process. -dns: an IP goes on the adapter; DoT/DoH
// go through a forwarder on 127.0.0.1:53 here; with any DNS setting nothing else reaches a DNS server.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
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

// the kill switch is on while this file exists: written once the filters are in, removed with them (1.0.1's marker
// in Program Files counts too until an elevated run carries it over)
func killSwitchMarker() string { return filepath.Join(dataDir, "killswitch.on") }

func killSwitchOn() bool {
	if _, err := os.Stat(killSwitchMarker()); err == nil {
		return true
	}
	if old := legacyProgramDir(); old != "" {
		if _, err := os.Stat(filepath.Join(old, "killswitch.on")); err == nil {
			return true
		}
	}
	return false
}

func liftKillSwitch() {
	firewall.Disable()
	os.Remove(killSwitchMarker())
}

// tunRun: from the first tunnel IP on. restart starts the client again bound to another physical address.
func tunRun(st *state, fail func(string) error, cl *clientRun, clientPath string, cport int, tip netip.Addr,
	serverDNS []string, o settings, ph physical, restart func(netip.Addr) (*clientRun, error)) error {
	keep := killSwitchOn() // an earlier tun's: a tun that fails leaves it on, as it found it
	mtu := envInt("MTU", o.MTU)
	dev, err := tun.CreateTUN(adapter, mtu)
	if err != nil {
		return fail("the tunnel adapter (wintun.dll next to csq-socks.exe?): " + err.Error())
	}
	cleanup := func(why string) error {
		if !keep {
			liftKillSwitch()
		}
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

	// the pump: one socket; the client's port can change when the client restarts on another network
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return cleanup("pump socket: " + err.Error())
	}
	uc.SetReadBuffer(4 << 20)
	uc.SetWriteBuffer(4 << 20)
	var dst atomic.Pointer[net.UDPAddr]
	dst.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cport})
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
				uc.WriteToUDP(bufs[i][:sizes[i]], dst.Load())
			}
		}
	}()
	go func() { // client → adapter
		buf := make([]byte, 65535)
		for {
			n, _, err := uc.ReadFromUDP(buf)
			if err != nil {
				time.Sleep(50 * time.Millisecond) // ICMP port unreachable before the client listens
				continue
			}
			dev.Write([][]byte{buf[:n]}, 0)
		}
	}()

	// the kill switch next, before any of our own traffic: an earlier tun's filters still in place only let its
	// adapter through, not this one. A DoH URL's host is looked up at the server's DNS: that server is allowed
	// until it is, then the filters are put in again without it.
	spec := env("DNS", o.DNS)
	if v, err := checkDNS(spec); err == nil {
		spec = v
	}
	loop := netip.MustParseAddr("127.0.0.1")
	var allowDNS, adapterDNS []netip.Addr
	var dohHost string
	switch {
	case spec == "default": // the system's DNS, now through the tunnel (or the LAN)
	case strings.HasPrefix(spec, "tls://") || strings.HasPrefix(spec, "https://"):
		allowDNS, adapterDNS = []netip.Addr{loop}, []netip.Addr{loop}
		if u, err := url.Parse(spec); err == nil && strings.HasPrefix(spec, "https://") {
			if _, err := netip.ParseAddr(u.Hostname()); err != nil {
				dohHost = u.Hostname()
			}
		}
	default:
		for _, d := range strings.Split(spec, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
				allowDNS = append(allowDNS, a)
			}
		}
		adapterDNS = allowDNS
	}
	bootstrap, _ := netip.ParseAddr(strings.TrimSpace(serverDNS[0]))
	setup := allowDNS
	if dohHost != "" && bootstrap.IsValid() {
		setup = append(append([]netip.Addr{}, allowDNS...), bootstrap)
	}
	if err := firewall.Enable(uint64(luid), clientPath, setup); err != nil {
		return cleanup("kill switch: " + err.Error())
	}
	os.WriteFile(killSwitchMarker(), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600)

	if allowDNS != nil && adapterDNS[0] == loop {
		// the forwarder's own connection goes out like any program's: through the tunnel
		dialTCP := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
		if dohHost != "" {
			res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, netip.AddrPortFrom(bootstrap, 53).String())
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ips, err := res.LookupNetIP(ctx, "ip4", dohHost)
			cancel()
			if err != nil || len(ips) == 0 {
				return cleanup(fmt.Sprintf("could not look up %s at %s: %v", dohHost, bootstrap, err))
			}
			pin, dial := ips[0].String(), dialTCP
			dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return dial(ctx, network, net.JoinHostPort(pin, port))
			}
			if err := firewall.Enable(uint64(luid), clientPath, allowDNS); err != nil { // the server's DNS out again
				return cleanup("kill switch: " + err.Error())
			}
		}
		pc, err := net.ListenPacket("udp", "127.0.0.1:53")
		if err != nil {
			return cleanup("the DNS forwarder needs 127.0.0.1:53, which is taken: " + err.Error())
		}
		r := newResolver(spec, dialTCP)
		go r.serveDNS(pc)
		go r.warm()
	}
	if adapterDNS != nil {
		if err := luid.SetDNS(windows.AF_INET, adapterDNS, nil); err != nil {
			return cleanup("adapter DNS: " + err.Error())
		}
	}

	st.Phase, st.TIP, st.DNS, st.Detail = "up", tip.String(), []string{spec}, ""
	st.Phys = ph.alias + " " + ph.ip.String()
	writeState(*st)

	// the client's sockets are bound to the physical address: when that changes (another Wi-Fi, a new lease, a
	// cable) the client is started again on the new one. The filters stay all along: blocked meanwhile, not leaked.
	blocked := func(why string) {
		st.Phase, st.Detail = "blocked", why+" — traffic is blocked until csq-socks down"
		writeState(*st)
	}
	for tick := time.NewTicker(5 * time.Second); ; {
		select {
		case f := <-cl.found: // a client started again is through
			port, _ := strconv.Atoi(f[0])
			dst.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if t, err := netip.ParseAddr(f[1]); err == nil && t != tip {
				tip = t
				luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(tip, 32)})
			}
			st.Phase, st.TIP, st.Detail = "up", tip.String(), ""
			writeState(*st)
		case <-cl.exited:
			blocked("the client exited")
			cl.exited = nil // a nil channel: from here on, only a network change starts it again
		case <-tick.C:
			p, err := physicalNet()
			if err != nil || p.ip == ph.ip {
				continue
			}
			ph = p
			st.Phase, st.Phys, st.Detail = "reconnecting", p.alias+" "+p.ip.String(), "the network changed"
			writeState(*st)
			if cl.exited != nil {
				cl.proc.Kill()
				<-cl.exited
			}
			if cl, err = restart(p.ip); err != nil {
				blocked("could not start the client again: " + err.Error())
				cl = &clientRun{}
			}
		}
	}
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
