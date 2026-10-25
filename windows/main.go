// csq-socks for Windows: one csqtt client on this machine, exposed as a SOCKS5 proxy on 127.0.0.1:PORT (default 1089).
// How: the client runs in its UDP mode (no --tun-uds: one raw IP packet per datagram on a 127.0.0.1 port), and a
// userspace TCP/IP stack in this program is the other end of that port — so only what you point at the proxy uses the
// tunnel; the machine's own routing is untouched, and no admin rights or driver are needed.
//
//	csq-socks set          — paste a csqtt:// link (2.1 plain or 2.5 sealed); saved to %APPDATA%\csq-socks\conn.json
//	csq-socks set -mtu N -dns X -port N -streams N
//	                       — settings, kept in settings.json beside it (a new link keeps them); with a link saved, no paste.
//	                         -dns: default (the server's DNS), an IP or IP,IP, tls://IP[:PORT][#NAME] (DoT),
//	                         https://URL (DoH). -X default, or -reset for all.
//	csq-socks up [PORT]    — connect; then use socks5h://127.0.0.1:PORT
//	csq-socks status       — client state, tunnel address, exit IP through the proxy, log tail
//	csq-socks down         — disconnect
//
// env (one run, over the settings): PORT (1089), N client streams (10), MTU (1500), DNS (as -dns), WAIT seconds to wait
//
//	for the tunnel (240; VK pauses 30–60 s on a flood), DEVID device id a 2.1 server binds the password to (csq-socks).
//
// 2.1 and 2.5 do not talk to each other: the link's form picks the client (client-2.1.9.exe or client-2.5.2.exe,
// next to this program). The connection lives in a background csq-socks process ("csq-socks daemon"), which holds
// the client in a job object: the client goes when it goes.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const version = "1.1"

var (
	exeDir  string
	cfgPath = filepath.Join(os.Getenv("APPDATA"), "csq-socks", "conn.json")
	run     = filepath.Join(os.Getenv("LOCALAPPDATA"), "csq-socks")
	logPath = filepath.Join(run, "client.log")
)

type state struct {
	Pid    int      `json:"pid"`
	Port   int      `json:"port"`
	Mode   string   `json:"mode"`
	Phase  string   `json:"phase"` // connecting | up | failed
	Detail string   `json:"detail,omitempty"`
	TIP    string   `json:"tunnel_ip,omitempty"`
	DNS    []string `json:"dns,omitempty"`
}

func main() {
	exe, _ := os.Executable()
	exeDir = filepath.Dir(exe)
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{""}
	}
	var err error
	switch args[0] {
	case "set":
		err = setLink(args[1:])
	case "up":
		if len(args) > 1 {
			os.Setenv("PORT", args[1])
		}
		err = up("socks")
	case "status":
		status()
	case "down":
		down()
		fmt.Println("down")
	case "daemon":
		err = daemon(args[1:])
	case "version":
		fmt.Println("csq-socks", version)
	default:
		fmt.Println("usage: csq-socks set | up [PORT] | status | down")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil && n > 0 {
		return n
	}
	return def
}

func setLink(flags []string) error {
	if len(flags) > 0 {
		o, err := applyOpts(loadOpts(), flags)
		if err != nil {
			return err
		}
		if err := saveOpts(o); err != nil {
			return err
		}
		fmt.Println("settings: " + o.String())
		if b, err := os.ReadFile(cfgPath); err == nil && len(b) > 0 {
			return nil
		}
	}
	fmt.Println("Paste the csqtt:// link, then Enter:")
	line, err := bufio.NewReaderSize(os.Stdin, 1<<16).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	c, err := parseLink(line)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	os.MkdirAll(filepath.Dir(cfgPath), 0o700)
	if err := os.WriteFile(cfgPath, append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("saved: csqtt %s server %s:%s, %d VK hash(es)\n", c.Line, c.Host, c.Port, len(c.Hashes))
	return nil
}

func loadConn() (conn, error) {
	var c conn
	b, err := os.ReadFile(cfgPath)
	if err != nil || len(b) == 0 {
		return c, fmt.Errorf("no connection saved — run: csq-socks set")
	}
	return c, json.Unmarshal(b, &c)
}

func readState() (state, bool) {
	var s state
	b, err := os.ReadFile(filepath.Join(run, "state.json"))
	if err != nil || json.Unmarshal(b, &s) != nil {
		return s, false
	}
	return s, true
}

func writeState(s state) {
	b, _ := json.Marshal(s)
	tmp := filepath.Join(run, "state.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(run, "state.json"))
	}
}

// alive: the pid still runs this very program (a reused pid is someone else's)
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil || code != 259 { // STILL_ACTIVE
		return false
	}
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return false
	}
	self, _ := os.Executable()
	return strings.EqualFold(windows.UTF16ToString(buf[:n]), self)
}

func up(mode string) error {
	c, err := loadConn()
	if err != nil {
		return err
	}
	if s, ok := readState(); ok && alive(s.Pid) {
		return fmt.Errorf("already up (%s) — csq-socks down first", s.Mode)
	}
	port := envInt("PORT", loadOpts().eff().Port)
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		return fmt.Errorf("port %d is in use — pick another: csq-socks up PORT", port)
	} else {
		l.Close()
	}
	down()
	os.MkdirAll(run, 0o700)
	os.WriteFile(logPath, nil, 0o600)
	self, _ := os.Executable()
	cmd := exec.Command(self, "daemon", mode, strconv.Itoa(port))
	cmd.Dir = exeDir
	// its own process, no console, out of the job a terminal or an ssh session puts this one in
	flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags | windows.CREATE_BREAKAWAY_FROM_JOB}
	if err := cmd.Start(); err != nil {
		cmd = exec.Command(self, "daemon", mode, strconv.Itoa(port))
		cmd.Dir = exeDir
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
		if err := cmd.Start(); err != nil {
			return err
		}
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()
	peer := net.JoinHostPort(c.Host, c.Port)
	fmt.Printf("connecting to %s (csqtt %s)…\n", peer, c.Line)
	wait := envInt("WAIT", 240)
	for i := 0; i < wait*4; i++ {
		time.Sleep(250 * time.Millisecond)
		s, ok := readState()
		if ok && s.Pid == pid && s.Phase == "up" {
			fmt.Printf("up: tunnel %s, DNS %s — SOCKS5 on 127.0.0.1:%d (use socks5h:// so names resolve through the tunnel)\n",
				s.TIP, strings.Join(s.DNS, ","), s.Port)
			return nil
		}
		if (ok && s.Pid == pid && s.Phase == "failed") || !alive(pid) {
			fmt.Printf("%s — client log tail:\n", firstNonEmpty(s.Detail, "the connection stopped"))
			logTail(20)
			down()
			return fmt.Errorf("not connected")
		}
	}
	fmt.Printf("no tunnel after %ds — client log tail:\n", wait)
	logTail(20)
	down()
	return fmt.Errorf("not connected")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func status() {
	s, ok := readState()
	if !ok || !alive(s.Pid) {
		fmt.Println("client: not running")
		fmt.Println("socks: not running")
	} else if s.Phase != "up" {
		fmt.Println("client: " + s.Phase)
	} else {
		fmt.Printf("client: running (Tunnel IP: %s)\n", s.TIP)
		fmt.Printf("socks: 127.0.0.1:%d\n", s.Port)
	}
	fmt.Println("settings: " + loadOpts().String())
	if ok && alive(s.Pid) && s.Phase == "up" {
		fmt.Printf("exit IP via proxy: %s\n", exitIP(s.Port))
	}
	if _, err := os.Stat(logPath); err == nil {
		fmt.Println("-- client log tail")
		logTail(5)
	}
}

func exitIP(port int) string {
	pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port)) // Go sends the name to the proxy either way
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	req, _ := http.NewRequest("GET", "https://ifconfig.me", nil)
	req.Header.Set("User-Agent", "curl/8")
	r, err := hc.Do(req)
	if err != nil {
		return "(no answer)"
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 256))
	return strings.TrimSpace(string(b))
}

func logTail(n int) {
	b, _ := os.ReadFile(logPath)
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
		if l != "" && !strings.Contains(l, "СТАТИСТИКА") {
			keep = append(keep, strings.TrimRight(l, "\r"))
		}
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	for _, l := range keep {
		fmt.Println(l)
	}
}

func down() {
	if s, ok := readState(); ok && alive(s.Pid) {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(s.Pid)); err == nil {
			windows.TerminateProcess(h, 0) // the job object takes the client with it
			windows.WaitForSingleObject(h, 5000)
			windows.CloseHandle(h)
		}
	}
	os.Remove(filepath.Join(run, "state.json"))
}

// killOnClose: a job whose last handle closing (this process ending, however it ends) kills every process in it
func killOnClose() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	return job, err
}

var (
	rePort = regexp.MustCompile(`\(порт (\d+)\)`)
	reTIP  = regexp.MustCompile(`Tunnel IP: ([0-9.]+)(?:/\d+)?(?: \| DNS: ([0-9.,]+))?`)
)

func daemon(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: csq-socks daemon MODE PORT")
	}
	mode := args[0]
	port, _ := strconv.Atoi(args[1])
	st := state{Pid: os.Getpid(), Port: port, Mode: mode, Phase: "connecting"}
	writeState(st)
	fail := func(why string) error {
		st.Phase, st.Detail = "failed", why
		writeState(st)
		return fmt.Errorf("%s", why)
	}
	c, err := loadConn()
	if err != nil {
		return fail(err.Error())
	}
	client, v21 := "client-2.1.9.exe", []string{"--password", c.Password, "--device-id", env("DEVID", "csq-socks")}
	if c.Line == "2.5" {
		client, v21 = "client-2.5.2.exe", nil
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fail(err.Error())
	}
	job, err := killOnClose()
	if err != nil {
		return fail("job object: " + err.Error())
	}
	cargs := append([]string{"--peer", net.JoinHostPort(c.Host, c.Port), "--vk", strings.Join(c.Hashes, ",")}, v21...)
	o := loadOpts().eff()
	cargs = append(cargs, "-n", env("N", strconv.Itoa(o.Streams)), "--listen", "127.0.0.1:0")
	cmd := exec.Command(filepath.Join(exeDir, client), cargs...)
	cmd.Env = append(os.Environ(), "CSQTT_PASSWORD="+c.Password)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return fail("could not start " + client + ": " + err.Error())
	}
	if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
		windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	exited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		fmt.Fprintf(pw, "client exited %v\n", err)
		pw.Close()
		close(exited)
	}()
	found := make(chan [3]string, 1) // client port, tunnel IP, DNS
	go func() {
		var cport string
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		sent := false
		for sc.Scan() {
			l := sc.Text()
			logf.WriteString(l + "\n")
			if m := rePort.FindStringSubmatch(l); m != nil && cport == "" {
				cport = m[1]
			}
			if m := reTIP.FindStringSubmatch(l); m != nil && !sent && cport != "" {
				found <- [3]string{cport, m[1], m[2]}
				sent = true
			}
		}
	}()
	var f [3]string
	select {
	case f = <-found:
	case <-exited:
		return fail("the client exited")
	}
	tip, err := netip.ParseAddr(f[1])
	if err != nil {
		return fail("bad tunnel IP " + f[1])
	}
	// DoT/DoH: the proxy asks that server; the stack keeps the server's DNS, for a DoH URL's own host
	spec, rdns := env("DNS", o.DNS), ""
	dnsList := strings.Split(firstNonEmpty(f[2], "1.1.1.1"), ",")
	switch {
	case spec == "default":
	case strings.HasPrefix(spec, "tls://") || strings.HasPrefix(spec, "https://"):
		rdns = spec
	default:
		dnsList = strings.Split(spec, ",")
	}
	var dns []netip.Addr
	for _, d := range dnsList {
		if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			dns = append(dns, a)
		}
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{tip}, dns, envInt("MTU", o.MTU))
	if err != nil {
		return fail("network stack: " + err.Error())
	}
	cport, _ := strconv.Atoi(f[0])
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cport})
	if err != nil {
		return fail("client port: " + err.Error())
	}
	uc.SetReadBuffer(1 << 20)
	uc.SetWriteBuffer(1 << 20)
	go func() { // stack → client
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				uc.Write(bufs[i][:sizes[i]])
			}
		}
	}()
	go func() { // client → stack
		buf := make([]byte, 65535)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				// the client not listening yet answers ICMP port unreachable, which Windows reports here
				time.Sleep(50 * time.Millisecond)
				continue
			}
			dev.Write([][]byte{buf[:n]}, 0)
		}
	}()
	ls, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fail(fmt.Sprintf("port %d: %v", port, err))
	}
	dial := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return tnet.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	st.Phase, st.TIP = "up", tip.String()
	if rdns != "" {
		r := newResolver(rdns, tnet)
		go r.warm()
		dial = r.dial
		st.DNS = []string{rdns}
	} else {
		for _, a := range dns {
			st.DNS = append(st.DNS, a.String())
		}
	}
	go serveSocks(ls, dial)
	writeState(st)
	<-exited
	ls.Close()
	return fail("the client exited")
}
