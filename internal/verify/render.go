package verify

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

// contentTypes are the Content-Type values creep writes for a Call's
// content type.
var contentTypes = map[string]string{
	contentJSON: "application/json",
	contentForm: "application/x-www-form-urlencoded",
	contentText: "text/plain; charset=utf-8",
}

// value is what replaces the payload placeholder: wire in a path or a
// form body, where it must stay URL-encoded, text in a JSON string or a
// text body.
type value struct{ wire, text string }

// fill is creep's side of one request: the nonce, the payload (or the
// baseline's harmless value) and the session header of a sequence.
type fill struct {
	nonce   string
	payload value
	session *Header
}

// render writes the raw HTTP/1.1 request for c to the app on port. The
// request line is in origin form and Host is always the app, so no
// parameter can send it anywhere else; every header line is checked text
// (Validate, session), so none can end early.
func render(c Call, port int, f fill) []byte {
	path := strings.ReplaceAll(c.Path, NoncePlaceholder, f.nonce)
	path = strings.ReplaceAll(path, PayloadPlaceholder, f.payload.wire)
	var b strings.Builder
	b.WriteString(c.Method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + sandbox.AppHost + ":" + strconv.Itoa(port) + "\r\n")
	for _, h := range c.Headers {
		b.WriteString(h.Name + ": " + strings.ReplaceAll(h.Value, NoncePlaceholder, f.nonce) + "\r\n")
	}
	if f.session != nil {
		b.WriteString(f.session.Name + ": " + f.session.Value + "\r\n")
	}
	body := renderBody(c, f)
	if c.ContentType != "" {
		b.WriteString("Content-Type: " + contentTypes[c.ContentType] + "\r\n")
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// renderBody places the nonce and the payload in the body, encoded for
// its content type.
func renderBody(c Call, f fill) string {
	body := strings.ReplaceAll(c.Body, NoncePlaceholder, f.nonce)
	switch c.ContentType {
	case contentForm:
		return strings.ReplaceAll(body, PayloadPlaceholder, f.payload.wire)
	case contentJSON:
		return strings.ReplaceAll(body, PayloadPlaceholder, jsonText(f.payload.text))
	}
	return strings.ReplaceAll(body, PayloadPlaceholder, f.payload.text)
}

// jsonText is s escaped for the inside of a JSON string.
func jsonText(s string) string {
	quoted, _ := json.Marshal(s) // a string always marshals
	return string(quoted[1 : len(quoted)-1])
}

// urlEncode percent-encodes every byte but RFC 3986 unreserved ones.
func urlEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}
