package main

// csqtt link → connection JSON, the same file link.py writes on Linux.
// Two link forms (swg-panel turn-artifacts.js csqttArtifact, the 2.5 server's encrypt_csqtt_link):
//   2.1: csqtt://connect?v=2&host=&peer=&password=&hashes=a+b   ('+' joins hashes, a literal '+' is %2B)
//   2.5: csqtt://<base64url(iv12 ‖ AES-256-GCM(payload) ‖ tag)>, key SHA-256("csqtt-chiper-key"), payload = the 2.1 query

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const seed = "csqtt-chiper-key" // sic — the csqtt authors' spelling

type conn struct {
	Line     string   `json:"line"`
	Host     string   `json:"host"`
	Port     string   `json:"port"`
	Password string   `json:"password"`
	Hashes   []string `json:"hashes"`
}

func unseal(blob string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(blob, "="))
	if err != nil || len(raw) < 12+16 {
		return "", errors.New("not a csqtt link: the sealed payload is not base64url")
	}
	key := sha256.Sum256([]byte(seed))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return "", errors.New("not a csqtt link: the sealed payload does not decrypt")
	}
	return string(plain), nil
}

func parseLink(link string) (conn, error) {
	link = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, link)
	if !strings.HasPrefix(link, "csqtt://") {
		return conn{}, errors.New("expected a csqtt:// link")
	}
	body, line := strings.TrimPrefix(link, "csqtt://"), "2.1"
	if !strings.HasPrefix(body, "connect?") {
		var err error
		if body, err = unseal(body); err != nil {
			return conn{}, err
		}
		line = "2.5"
	}
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[i+1:]
	}
	q := map[string]string{}
	for _, kv := range strings.Split(body, "&") {
		k, v, _ := strings.Cut(kv, "=")
		q[k] = v
	}
	unq := func(s string) string {
		if u, err := url.PathUnescape(s); err == nil {
			return u
		}
		return s
	}
	c := conn{Line: line, Host: strings.Trim(unq(q["host"]), "[]"), Port: q["peer"], Password: unq(q["password"]), Hashes: []string{}}
	for _, h := range strings.Split(q["hashes"], "+") {
		if h != "" {
			c.Hashes = append(c.Hashes, unq(h))
		}
	}
	if _, err := strconv.Atoi(c.Port); c.Host == "" || err != nil {
		return conn{}, errors.New("the link has no host or port")
	}
	if c.Password == "" {
		return conn{}, errors.New("the link has no password")
	}
	if !reachable(c.Host) {
		return conn{}, fmt.Errorf("the link's server address %s is a private address (the server's own network or a tunnel), "+
			"which VK's relays cannot reach — copy the link from the server's panel opened by its public address", c.Host)
	}
	return c, nil // no hashes (a link with a VK token, or one a participant adds their own to): set says to add them
}

func reachable(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true // a name
	}
	return !(ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate())
}

// csq-socks set -hash: VK call hashes to add, space or comma separated; a …/call/join/<hash> link gives its hash
var reHash = regexp.MustCompile(`^[A-Za-z0-9_+=.-]{10,}$`)

func parseHashes(vals []string) ([]string, error) {
	var out []string
	for _, v := range vals {
		for _, h := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
			if i := strings.Index(h, "/call/join/"); i >= 0 {
				h = h[i+len("/call/join/"):]
				h = strings.TrimRight(strings.SplitN(strings.SplitN(h, "?", 2)[0], "#", 2)[0], "/")
			}
			if !reHash.MatchString(h) {
				return nil, fmt.Errorf("-hash: %q is not a VK call hash (or a …/call/join/<hash> link)", h)
			}
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-hash needs a VK call hash")
	}
	return out, nil
}

// addHashes: the new ones, in order, none twice; how many were new
func (c *conn) addHashes(hs []string) int {
	have := map[string]bool{}
	for _, h := range c.Hashes {
		have[h] = true
	}
	n := 0
	for _, h := range hs {
		if !have[h] {
			have[h] = true
			c.Hashes = append(c.Hashes, h)
			n++
		}
	}
	return n
}
