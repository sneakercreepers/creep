package verify

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// ErrInvalid marks a PoC that is refused before anything runs: an unknown
// template, parameters that break the schema, or a PoC Build did not make.
var ErrInvalid = errors.New("poc refused")

// PoC is a validated Request with the fresh nonce its oracle looks for.
// Only Build makes one, so Run never sees parameters that were not
// checked.
type PoC struct {
	req   Request
	nonce string // "creep" and 24 lowercase hex digits
}

// Template is the PoC's template ID.
func (p PoC) Template() string { return p.req.Template }

// Build checks the model's Request and makes a PoC of it. The request is
// copied first, so changing it afterwards changes nothing that runs.
func Build(req Request) (PoC, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return PoC{}, fmt.Errorf("poc nonce: %w", err)
	}
	return build(req, "creep"+hex.EncodeToString(b[:]))
}

func build(req Request, nonce string) (PoC, error) {
	c := cloneRequest(req)
	if err := c.Validate(); err != nil {
		return PoC{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return PoC{req: c, nonce: nonce}, nil
}

func cloneRequest(r Request) Request {
	out := Request{Template: r.Template}
	if p := r.HTTPRequest; p != nil {
		c := *p
		c.Request = cloneCall(c.Request)
		out.HTTPRequest = &c
	}
	if p := r.HTTPSequence; p != nil {
		c := *p
		c.Auth, c.Request = cloneCall(c.Auth), cloneCall(c.Request)
		out.HTTPSequence = &c
	}
	if p := r.SQLPayload; p != nil {
		c := *p
		c.Request = cloneCall(c.Request)
		out.SQLPayload = &c
	}
	if p := r.PathPayload; p != nil {
		c := *p
		c.Request = cloneCall(c.Request)
		out.PathPayload = &c
	}
	return out
}

func cloneCall(c Call) Call {
	c.Headers = slices.Clone(c.Headers)
	return c
}

// marker is the table a marker SQL payload creates: creep's name, from
// the nonce, never the model's.
func (p PoC) marker() string { return "creep_" + p.nonce[len("creep"):] }
