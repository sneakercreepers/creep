package redact

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var errTestDeadline = errors.New("test deadline")

// Protection (#260): a Redactor bound to a run's context stops inside a
// call once the context is done, returns its cause and no text, and
// remembers nothing from the stopped call, so a deadline can never yield a
// partly redacted file. Without a context, or before it is done, it redacts
// as New does.
func TestRedactorStopsWithContext(t *testing.T) {
	const secret = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	tests := []struct {
		name    string
		cancel  bool // cancel with errTestDeadline before the call
		file    bool // File instead of Redact
		wantErr error
	}{
		{"file, live context", false, true, nil},
		{"redact, live context", false, false, nil},
		{"file, done context", true, true, errTestDeadline},
		{"redact, done context", true, false, errTestDeadline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			r, err := NewWithContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tt.cancel {
				cancel(errTestDeadline)
			}
			text := "token = " + secret + "\n"
			var out string
			if tt.file {
				out, err = r.File([]byte(text))
			} else {
				out, err = r.Redact(text)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if strings.Contains(out, secret) {
				t.Fatalf("output holds the secret: %q", out)
			}
			if tt.wantErr != nil && (out != "" || len(r.state.byValue) != 0) {
				t.Fatalf("stopped call returned %q and stored %d values", out, len(r.state.byValue))
			}
			if tt.wantErr == nil && len(r.state.byValue) != 1 {
				t.Fatalf("live call stored %d values, want 1", len(r.state.byValue))
			}
		})
	}
}

// Protection (#260): a file at the cap crafted to wake every rule takes
// minutes (MaxFileBytes); once the context expires, File returns within
// one detector's pass, not at the end of the file, and drops its output.
func TestFileStopsInsideCraftedFile(t *testing.T) {
	head := keywordLines(t)
	shapes := map[string]string{
		"short lines":              head + wordLines(MaxFileBytes-len(head), 100),
		"short lines, format char": withFormatChar(head + wordLines(MaxFileBytes-len(head), 100)),
	}
	bound := 10 * time.Second
	if raceEnabled {
		bound *= 15
	}
	for name, text := range shapes {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			r, err := NewWithContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			out, err := r.File([]byte(text))
			if took := time.Since(start); took > bound {
				t.Fatalf("File took %v after a 200ms deadline, want under %v", took, bound)
			}
			if !errors.Is(err, context.DeadlineExceeded) || out != "" {
				t.Fatalf("File = %d bytes, %v; want no text and the deadline", len(out), err)
			}
		})
	}
}
