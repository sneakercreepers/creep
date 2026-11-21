package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Bounds on the model's parameters. With creep's payloads, session and
// headers on top, a request stays far below sandbox.MaxRequestBytes.
const (
	maxPath        = 1024
	maxHeaders     = 8
	maxHeaderValue = 1024
	maxBody        = 8 << 10
	maxNonces      = 4
	maxDepth       = 12
)

// Content types a Call may name; creep writes the header itself.
const (
	contentJSON = "json"
	contentForm = "form"
	contentText = "text"
)

var methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// allowedHeaders are the only header names a model may set, spelled
// exactly so. Host, Content-Type, Content-Length, Connection, Transfer-
// Encoding and every other framing or routing header are creep's.
var allowedHeaders = []string{
	"Accept", "Accept-Language", "Authorization", "Cookie", "Origin", "Referer",
	"User-Agent", "X-Api-Key", "X-Csrf-Token", "X-Forwarded-For", "X-Requested-With",
}

// pathByte is the alphabet of a path and query: RFC 3986 unreserved,
// sub-delims, ":", "@", "/", "?" and "%" (checked as an escape). No space,
// "#", "\", quote or control byte, so the path cannot end the request
// line or name another host.
func pathByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("-._~!$&'()*+,;=:@/?%", c) >= 0
}

// Validate checks every rule JSON decoding cannot. Its messages state the
// rule and never quote a value: they may go back into a prompt.
func (r *Request) Validate() error {
	set := 0
	for _, p := range []bool{r.HTTPRequest != nil, r.HTTPSequence != nil, r.SQLPayload != nil, r.PathPayload != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return errors.New("exactly one template's parameters must be set")
	}
	switch {
	case r.Template == TemplateHTTPRequest && r.HTTPRequest != nil:
		return r.HTTPRequest.validate()
	case r.Template == TemplateHTTPSequence && r.HTTPSequence != nil:
		return r.HTTPSequence.validate()
	case r.Template == TemplateSQLPayload && r.SQLPayload != nil:
		return r.SQLPayload.validate()
	case r.Template == TemplatePathPayload && r.PathPayload != nil:
		return r.PathPayload.validate()
	}
	return errors.New("template must be http_request, http_sequence, sql_payload or path_payload, with its own parameters")
}

func (p *HTTPRequest) validate() error {
	if err := validateCall(p.Request, "request"); err != nil {
		return err
	}
	return validateOracle(p.Oracle, p.Request)
}

func (p *HTTPSequence) validate() error {
	if err := validateCall(p.Auth, "auth"); err != nil {
		return err
	}
	if placeholders(p.Auth, NoncePlaceholder).total()+placeholders(p.Auth, PayloadPlaceholder).total() > 0 {
		return errors.New("auth must not hold a placeholder")
	}
	if err := validateCall(p.Request, "request"); err != nil {
		return err
	}
	switch {
	case p.Session == "cookie" && p.TokenField == "" && !hasHeader(p.Request, "Cookie"):
	case p.Session == "bearer" && tokenField(p.TokenField) && !hasHeader(p.Request, "Authorization"):
	default:
		return errors.New("session must be cookie (no token_field, no Cookie header on request) or bearer (a token_field of letters, digits and _, no Authorization header on request)")
	}
	return validateOracle(p.Oracle, p.Request)
}

func (p *SQLPayload) validate() error {
	if err := validatePayloadCall(p.Request); err != nil {
		return err
	}
	if p.Context != "string" && p.Context != "numeric" {
		return errors.New("context must be string or numeric")
	}
	if p.Technique != "delay" && p.Technique != "marker" {
		return errors.New("technique must be delay or marker")
	}
	return nil
}

func (p *PathPayload) validate() error {
	if err := validatePayloadCall(p.Request); err != nil {
		return err
	}
	switch {
	case p.Style == "absolute" && p.Depth == 0:
	case (p.Style == "relative" || p.Style == "encoded") && p.Depth >= 1 && p.Depth <= maxDepth:
	default:
		return fmt.Errorf("style must be relative or encoded with depth 1 to %d, or absolute with depth 0", maxDepth)
	}
	return nil
}

// validateOracle: status names a status code and holds no nonce; reflect
// needs the nonce placeholder in the request, at most maxNonces times.
// Neither has a payload.
func validateOracle(o Oracle, c Call) error {
	if placeholders(c, PayloadPlaceholder).total() > 0 {
		return errors.New("request must not hold the payload placeholder")
	}
	n := placeholders(c, NoncePlaceholder).total()
	switch {
	case o.Kind == OracleStatus && o.Status >= 100 && o.Status <= 599 && n == 0:
		return nil
	case o.Kind == OracleReflect && o.Status == 0 && n >= 1 && n <= maxNonces:
		return nil
	}
	return fmt.Errorf("oracle must be status with a status from 100 to 599 and no nonce placeholder, or reflect with status 0 and the nonce placeholder 1 to %d times", maxNonces)
}

// validatePayloadCall: one payload placeholder, in the path or the body,
// and no nonce.
func validatePayloadCall(c Call) error {
	if err := validateCall(c, "request"); err != nil {
		return err
	}
	p := placeholders(c, PayloadPlaceholder)
	if p.path+p.body != 1 || placeholders(c, NoncePlaceholder).total() != 0 {
		return errors.New("request must hold the payload placeholder exactly once, in its path or body, and no nonce placeholder")
	}
	return nil
}

// validateCall checks one request's method, path, headers and body. Only
// the payload templates may hold the payload placeholder, and never in a
// header (checkPlacement).
func validateCall(c Call, what string) error {
	if !slices.Contains(methods, c.Method) {
		return fmt.Errorf("%s method must be GET, POST, PUT, PATCH or DELETE", what)
	}
	if !validPath(c.Path) {
		return fmt.Errorf("%s path must start with one /, be at most %d bytes and use only URL path and query characters", what, maxPath)
	}
	if err := validateHeaders(c.Headers); err != nil {
		return fmt.Errorf("%s %w", what, err)
	}
	if err := validateBody(c); err != nil {
		return fmt.Errorf("%s %w", what, err)
	}
	if p := placeholders(c, PayloadPlaceholder); p.headers > 0 {
		return fmt.Errorf("%s headers must not hold the payload placeholder", what)
	}
	return nil
}

func validPath(p string) bool {
	if len(p) == 0 || len(p) > maxPath || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !pathByte(p[i]) || p[i] == '%' && !hexEscape(p, i) {
			return false
		}
	}
	return true
}

func hexEscape(s string, i int) bool {
	return i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2])
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func validateHeaders(headers []Header) error {
	if len(headers) > maxHeaders {
		return fmt.Errorf("must have at most %d headers", maxHeaders)
	}
	seen := map[string]bool{}
	for _, h := range headers {
		if !slices.Contains(allowedHeaders, h.Name) || seen[h.Name] {
			return fmt.Errorf("header names must be distinct and one of %s", strings.Join(allowedHeaders, ", "))
		}
		seen[h.Name] = true
		if !headerValue(h.Value, maxHeaderValue) {
			return fmt.Errorf("header values must be 1 to %d printable ASCII characters, with no space at either end", maxHeaderValue)
		}
	}
	return nil
}

// headerValue is printable ASCII and space, not empty and not padded, so
// it can never end the header line.
func headerValue(v string, limit int) bool {
	if v == "" || len(v) > limit || v[0] == ' ' || v[len(v)-1] == ' ' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// validateBody: a body only with a content type, only on a method that
// carries one, bounded, and well formed for its type.
func validateBody(c Call) error {
	if c.ContentType == "" {
		if c.Body != "" {
			return errors.New("body needs a content_type")
		}
		return nil
	}
	ok := c.Method != "GET" && c.Body != "" && len(c.Body) <= maxBody && utf8.ValidString(c.Body) && !strings.ContainsRune(c.Body, 0)
	switch c.ContentType {
	case contentJSON:
		ok = ok && json.Valid([]byte(c.Body))
	case contentForm:
		ok = ok && formBody(c.Body)
	case contentText:
	default:
		return errors.New("content_type must be empty, json, form or text")
	}
	if !ok {
		return fmt.Errorf("body must be 1 to %d bytes of UTF-8 on a method other than GET, valid JSON for json and URL-encoded for form", maxBody)
	}
	return nil
}

func formBody(b string) bool {
	for i := 0; i < len(b); i++ {
		if !pathByte(b[i]) || b[i] == '%' && !hexEscape(b, i) {
			return false
		}
	}
	return true
}

func hasHeader(c Call, name string) bool {
	return slices.ContainsFunc(c.Headers, func(h Header) bool { return h.Name == name })
}

func tokenField(f string) bool {
	if f == "" || len(f) > 64 || '0' <= f[0] && f[0] <= '9' {
		return false
	}
	for i := 0; i < len(f); i++ {
		if c := f[i]; c != '_' && !isAlnum(c) {
			return false
		}
	}
	return true
}

// counts is where a placeholder appears in a Call.
type counts struct{ path, headers, body int }

func (c counts) total() int { return c.path + c.headers + c.body }

func placeholders(c Call, ph string) counts {
	n := counts{path: strings.Count(c.Path, ph), body: strings.Count(c.Body, ph)}
	for _, h := range c.Headers {
		n.headers += strings.Count(h.Value, ph)
	}
	return n
}
