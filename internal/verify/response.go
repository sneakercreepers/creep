package verify

import (
	"bytes"
	"strconv"
	"strings"
)

// Bounds on reading a response. The response itself is at most
// sandbox.MaxResponseBytes.
const (
	maxHead         = 32 << 10
	maxHeaderFields = 128
)

// response is one parsed HTTP response from the app: hostile bytes, read
// only to judge an oracle and to take a session from.
type response struct {
	status  int
	headers []Header // as sent; names compared case-insensitively
	body    []byte   // chunked transfer coding removed
}

// parseResponse reads an HTTP/1.x response. Anything without a status
// line and an end of header is no response.
func parseResponse(raw []byte) (response, bool) {
	head, body, ok := splitHead(raw)
	if !ok {
		return response{}, false
	}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	status, ok := statusCode(lines[0])
	if !ok || len(lines)-1 > maxHeaderFields {
		return response{}, false
	}
	r := response{status: status, body: body}
	for _, line := range lines[1:] {
		name, v, found := strings.Cut(line, ":")
		if found && name != "" && !strings.ContainsAny(name, " \t") {
			r.headers = append(r.headers, Header{Name: name, Value: strings.TrimSpace(v)})
		}
	}
	if chunked(r.headers) {
		if decoded, ok := dechunk(body); ok {
			r.body = decoded
		}
	}
	return r, true
}

// splitHead cuts raw at the first empty line, CRLF or bare LF.
func splitHead(raw []byte) (string, []byte, bool) {
	crlf := bytes.Index(raw, []byte("\r\n\r\n"))
	lf := bytes.Index(raw, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf < lf) && crlf <= maxHead:
		return string(raw[:crlf]), raw[crlf+4:], true
	case lf >= 0 && lf <= maxHead:
		return string(raw[:lf]), raw[lf+2:], true
	}
	return "", nil, false
}

// statusCode reads "HTTP/1.0 200 OK" or "HTTP/1.1 404".
func statusCode(line string) (int, bool) {
	f := strings.Fields(line)
	if len(f) < 2 || (f[0] != "HTTP/1.1" && f[0] != "HTTP/1.0") || len(f[1]) != 3 {
		return 0, false
	}
	code, err := strconv.Atoi(f[1])
	if err != nil || code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}

func (r response) values(name string) []string {
	var out []string
	for _, h := range r.headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

func chunked(headers []Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Transfer-Encoding") {
			codings := strings.Split(h.Value, ",")
			return strings.EqualFold(strings.TrimSpace(codings[len(codings)-1]), "chunked")
		}
	}
	return false
}

// dechunk removes the chunked transfer coding. It never reads past body
// and stops at the last chunk; a malformed one fails, and the caller keeps
// the raw body.
func dechunk(body []byte) ([]byte, bool) {
	var out []byte
	for {
		line, rest, ok := bytes.Cut(body, []byte("\n"))
		if !ok {
			return nil, false
		}
		sizeText, _, _ := strings.Cut(strings.TrimSpace(string(line)), ";")
		size, err := strconv.ParseUint(sizeText, 16, 31)
		if err != nil || uint64(len(rest)) < size {
			return nil, false
		}
		if size == 0 {
			return out, true
		}
		out = append(out, rest[:size]...)
		body = bytes.TrimPrefix(bytes.TrimPrefix(rest[size:], []byte("\r")), []byte("\n"))
	}
}

// html reports whether the response names a Content-Type and every one it
// names is HTML: only there is creep's probe, unescaped, markup a browser
// would parse.
func (r response) html() bool {
	types := r.values("Content-Type")
	if len(types) == 0 {
		return false
	}
	for _, v := range types {
		media, _, _ := strings.Cut(v, ";")
		if m := strings.ToLower(strings.TrimSpace(media)); m != "text/html" && m != "application/xhtml+xml" {
			return false
		}
	}
	return true
}
