package verify

import (
	"encoding/json"
	"strings"
)

// Bounds on the session taken from an auth response.
const (
	maxCookies     = 8
	maxCookieName  = 64
	maxCookieValue = 1024
	maxToken       = 4096
)

// session takes the session an http_sequence's auth response gave: its
// cookies, or the bearer token in one top-level string field of its JSON
// body. The values come from the app, so each is checked to a header-safe
// alphabet before it goes into the next request; anything else is no
// session.
func session(kind, field string, auth response) (Header, bool) {
	if kind == "bearer" {
		return bearer(field, auth.body)
	}
	return cookies(auth.values("Set-Cookie"))
}

func cookies(setCookies []string) (Header, bool) {
	var pairs []string
	seen := map[string]bool{}
	for _, sc := range setCookies {
		pair, _, _ := strings.Cut(sc, ";")
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || !cookieName(name) || !cookieValue(value) || seen[name] {
			continue
		}
		seen[name] = true
		pairs = append(pairs, name+"="+value)
		if len(pairs) == maxCookies {
			break
		}
	}
	if len(pairs) == 0 {
		return Header{}, false
	}
	return Header{Name: "Cookie", Value: strings.Join(pairs, "; ")}, true
}

// cookieName is an RFC 6265 token.
func cookieName(s string) bool {
	if s == "" || len(s) > maxCookieName {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f || strings.IndexByte(`()<>@,;:\"/[]?={}`, c) >= 0 {
			return false
		}
	}
	return true
}

// cookieValue is RFC 6265 cookie-octets: no space, quote, comma,
// semicolon, backslash or control byte.
func cookieValue(s string) bool {
	if s == "" || len(s) > maxCookieValue {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f || strings.IndexByte(`",;\`, c) >= 0 {
			return false
		}
	}
	return true
}

func bearer(field string, body []byte) (Header, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return Header{}, false
	}
	var token string
	if raw, ok := fields[field]; !ok || json.Unmarshal(raw, &token) != nil || !tokenValue(token) {
		return Header{}, false
	}
	return Header{Name: "Authorization", Value: "Bearer " + token}, true
}

// tokenValue is visible ASCII with no space, so it stays one header value.
func tokenValue(s string) bool {
	if s == "" || len(s) > maxToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
