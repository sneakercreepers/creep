package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ErrResponseStalled means a response body stopped sending bytes for the
// idle limit, or did not finish within the total limit after its headers.
var ErrResponseStalled = errors.New("response body stalled")

// watchedBody cancels its request when the body goes idle or runs past its
// deadline, so a server that sends headers and then trickles cannot hang a
// call. Each read that brings bytes restarts the idle wait, so a steady
// stream keeps working.
type watchedBody struct {
	io.ReadCloser
	cancel   context.CancelFunc
	idle     time.Duration
	deadline time.Time
	timer    *time.Timer
	stalled  atomic.Bool
}

func watchBody(rc io.ReadCloser, cancel context.CancelFunc, limits timeLimits) *watchedBody {
	b := &watchedBody{ReadCloser: rc, cancel: cancel, idle: limits.bodyIdle, deadline: time.Now().Add(limits.bodyTotal)}
	b.timer = time.AfterFunc(b.wait(), b.expire)
	return b
}

// wait is the idle limit, cut short by the total deadline.
func (b *watchedBody) wait() time.Duration {
	return min(b.idle, time.Until(b.deadline))
}

func (b *watchedBody) expire() {
	b.stalled.Store(true)
	b.cancel()
}

func (b *watchedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	// After expire, any end of the body is ours: canceling can make the
	// server stop writing and close the stream cleanly, which reads as EOF.
	if err != nil && b.stalled.Load() {
		return n, fmt.Errorf("read response: %w", ErrResponseStalled)
	}
	if n > 0 {
		b.timer.Reset(b.wait())
	}
	return n, err
}

func (b *watchedBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
