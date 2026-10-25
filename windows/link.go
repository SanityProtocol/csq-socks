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
	"net/url"
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
	if len(c.Hashes) == 0 {
		return conn{}, errors.New("the link carries no VK call hashes — add a VK call link to this user in the panel first")
	}
	return c, nil
}
