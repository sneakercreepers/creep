package redact

import (
	"context"
	"fmt"
)

// NewWithContext returns a Redactor like New whose File and Redact calls stop
// once ctx is done (#260): a file crafted to wake every rule takes minutes
// (MaxFileBytes), so a run deadline must reach inside a call, not only
// between calls. A stopped call returns ctx's cause and no text: the spans it
// found so far are incomplete, so its output is dropped and nothing it found
// is remembered. Callers that hold the Redactor (the reader's slicer,
// discovery, the gateway's FileScan) see an ordinary File error and list the
// file as not scanned.
func NewWithContext(ctx context.Context) (*Redactor, error) {
	r, err := New()
	if err != nil {
		return nil, err
	}
	r.ctx = ctx
	return r, nil
}

// done is the context's Done channel, or nil (never done) without one.
func (r *Redactor) done() <-chan struct{} {
	if r.ctx == nil {
		return nil
	}
	return r.ctx.Done()
}

// stopped returns the context's cause once it is done, or nil.
func (r *Redactor) stopped() error {
	if r.ctx == nil || r.ctx.Err() == nil {
		return nil
	}
	return fmt.Errorf("redact stopped: %w", context.Cause(r.ctx))
}

// stopped reports whether the detectors must stop searching: the run's
// context is done, and the caller drops whatever was found.
func (s detectorSet) stopped() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
