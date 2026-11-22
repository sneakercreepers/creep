package verify

import (
	"bytes"
	"slices"
	"strings"
)

// HeaderMask replaces a credential header's value, and every copy of
// a session value, in a bundle step.
const HeaderMask = "<CREDENTIAL>"

// minCredential is the shortest session value masked wherever it appears:
// a shorter one is no secret, and masking it would garble unrelated text.
const minCredential = 8

// credentialHeaders carry a session or a key. redact.File finds no rule in
// an opaque cookie or bearer token, so a bundle never keeps their values,
// whatever the app issued (#25).
var credentialHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-csrf-token": true,
}

// maskCredentials masks the values of the credential headers in every
// step of one run, and each value of them wherever it appears in the run:
// the token an auth response hands back in its body is the one the next
// request sends.
func maskCredentials(steps []Step) [][2][]byte {
	var values []string
	for _, s := range steps {
		values = append(values, headerCredentials(s.Request)...)
		values = append(values, headerCredentials(s.Response)...)
	}
	// Longest first, so a value inside another is not masked half.
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	out := make([][2][]byte, len(steps))
	for i, s := range steps {
		out[i] = [2][]byte{maskMessage(s.Request, values), maskMessage(s.Response, values)}
	}
	return out
}

// maskMessage masks the credential header lines of one HTTP message, then
// every session value in what is left.
func maskMessage(msg []byte, values []string) []byte {
	head, body := splitMessage(msg)
	lines := bytes.SplitAfter(head, []byte("\n"))
	for i, line := range lines {
		if name, _, ok := headerLine(line); ok && credentialHeaders[name] {
			lines[i] = []byte(string(line[:bytes.IndexByte(line, ':')+1]) + " " + HeaderMask + lineEnd(line))
		}
	}
	text := string(bytes.Join(lines, nil)) + string(body)
	for _, v := range values {
		text = strings.ReplaceAll(text, v, HeaderMask)
	}
	return []byte(text)
}

// headerCredentials are the values worth masking anywhere in a run: each
// credential header's whole value, its scheme-less token and each cookie.
func headerCredentials(msg []byte) []string {
	head, _ := splitMessage(msg)
	var out []string
	for line := range bytes.Lines(head) {
		name, value, ok := headerLine(line)
		if !ok || !credentialHeaders[name] {
			continue
		}
		out = append(out, credentialParts(name, value)...)
	}
	return slices.DeleteFunc(out, func(v string) bool { return len(v) < minCredential })
}

// credentialParts are a header's whole value and the secrets inside it:
// the token after a scheme ("Bearer x"), every cookie of a Cookie header,
// and the cookie a Set-Cookie sets (its attributes are no secret).
func credentialParts(name, value string) []string {
	parts := []string{value}
	switch name {
	case "cookie":
		for pair := range strings.SplitSeq(value, ";") {
			parts = append(parts, cookiePairValue(pair))
		}
	case "set-cookie":
		first, _, _ := strings.Cut(value, ";")
		parts = append(parts, cookiePairValue(first))
	default:
		if _, token, ok := strings.Cut(value, " "); ok {
			parts = append(parts, strings.TrimSpace(token))
		}
	}
	return parts
}

func cookiePairValue(pair string) string {
	_, v, _ := strings.Cut(pair, "=")
	return strings.Trim(strings.TrimSpace(v), `"`)
}

// headerLine is one "Name: value" line of a message head, its name in
// lower case; the request or status line is not one.
func headerLine(line []byte) (name, value string, ok bool) {
	n, v, ok := strings.Cut(strings.TrimRight(string(line), "\r\n"), ":")
	if !ok || n == "" || strings.ContainsAny(n, " \t/") {
		return "", "", false
	}
	return strings.ToLower(n), strings.TrimSpace(v), true
}

// splitMessage splits an HTTP message at its first empty line, CRLF or LF;
// a message with none is all head.
func splitMessage(msg []byte) (head, body []byte) {
	for i := 0; i < len(msg); i++ {
		if msg[i] != '\n' {
			continue
		}
		rest := msg[i+1:]
		switch {
		case bytes.HasPrefix(rest, []byte("\r\n")):
			return msg[:i+3], msg[i+3:]
		case bytes.HasPrefix(rest, []byte("\n")):
			return msg[:i+2], msg[i+2:]
		}
	}
	return msg, nil
}

func lineEnd(line []byte) string {
	switch {
	case bytes.HasSuffix(line, []byte("\r\n")):
		return "\r\n"
	case bytes.HasSuffix(line, []byte("\n")):
		return "\n"
	}
	return ""
}
