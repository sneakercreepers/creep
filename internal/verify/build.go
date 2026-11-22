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

// PoC is a validated Request. Only Build makes one, so Run never sees
// parameters that were not checked.
type PoC struct {
	req   Request
	built bool
}

// Template is the PoC's template ID.
func (p PoC) Template() string { return p.req.Template }

// Build checks the model's Request and makes a PoC of it. The request is
// copied first, so changing it afterwards changes nothing that runs.
func Build(req Request) (PoC, error) {
	c := cloneRequest(req)
	if err := c.Validate(); err != nil {
		return PoC{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return PoC{req: c, built: true}, nil
}

// newNonce is a fresh nonce for one run: "creep" and 24 lowercase hex
// digits. Each run gets its own, so what an earlier run left behind (a
// marker table, a stored probe) never verifies a later one.
func newNonce() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("poc nonce: %w", err)
	}
	return "creep" + hex.EncodeToString(b[:]), nil
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

// markerTable is the table a marker SQL payload creates: creep's name,
// from the run's nonce, never the model's.
func markerTable(nonce string) string { return "creep_" + nonce[len("creep"):] }
