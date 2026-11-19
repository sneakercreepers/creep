package sandbox

import (
	"context"
	"fmt"
)

// maxBatch bounds the containers of one RunBatch.
const maxBatch = 64

// RunBatch runs PoC containers on the run's internal network, one after
// the other. Before the first one starts, the canary must show that the
// network reaches nothing outside; if it reaches anything, or cannot tell,
// no container of the batch starts and the run is aborted: every later
// Run, RunBatch or StartDatabase returns the same error. It returns the
// results of the containers that finished, in order, and stops at the
// first error.
func (s *Sandbox) RunBatch(ctx context.Context, specs []Spec) ([]Result, error) {
	if len(specs) == 0 || len(specs) > maxBatch {
		return nil, fmt.Errorf("batch of %d containers outside 1..%d: %w", len(specs), maxBatch, ErrSpec)
	}
	if err := s.clearNetwork(ctx); err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(specs))
	for _, spec := range specs {
		spec.networked, spec.alias, spec.detach, spec.tmpfs = true, "", false, nil
		res, err := s.start(ctx, spec)
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// clearNetwork is the gate in front of every container that joins the
// network: the run must not be aborted, the network must exist, and the
// canary must pass now. A canary that fails aborts the run.
func (s *Sandbox) clearNetwork(ctx context.Context) error {
	if err := s.abortErr(); err != nil {
		return err
	}
	if err := s.ensureNetwork(ctx); err != nil {
		return err
	}
	if err := s.canary(ctx); err != nil {
		s.abort(err)
		return fmt.Errorf("run aborted: %w", err)
	}
	return nil
}

func (s *Sandbox) abort(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted == nil {
		s.aborted = err
	}
}

// abortErr is the error that aborted the run, or nil.
func (s *Sandbox) abortErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted == nil {
		return nil
	}
	return fmt.Errorf("run aborted: %w", s.aborted)
}
