package cli

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// Acceptance (#358, ADR 0037): the same model gets the same calibration,
// and so the same tier, whatever languages the scanned repository holds.
// A real calibration runs once against replayed replies on a Go-only
// repository; scans of a Python-only and a mixed repository are served
// the same cached result with no calibration call, because nothing from
// the repository reaches the task set or the cache key.
func TestCalibrationIgnoresRepositoryLanguages(t *testing.T) {
	store, err := state.OpenWithSecret(t.TempDir(), make([]byte, state.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m := &fakeModel{}
	send, calCalls := alwaysSafeCalibration(m.send)
	var got []calibrate.Calibration
	deps := scanDeps{
		connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
			return modelLink{send: send, close: func() error { return nil }}, nil
		},
		calibrate: func(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
			opts.Store, opts.Now = store, func() time.Time { return time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC) }
			c, err := calibrate.RunCached(ctx, opts)
			got = append(got, c)
			return c, err
		},
	}
	// scanRepo moves into the repository, so the apps are read first.
	flask, express := testApp(t, "flask"), testApp(t, "express")
	repos := []map[string]string{
		{"main.go": "package main\n\nfunc main() {}\n"},
		{"app.py": flask},
		{"server.js": express, "lib/util.rb": "puts 1\n", "Main.java": "class Main {}\n"},
	}
	for i, files := range repos {
		before := *calCalls
		cfg := scanRepo(t, files, "")
		code, _, stderr := runScanWith(deps, "scan", "--config", cfg)
		// The replayed model calls everything safe, so the floor refuses it
		// on every repository alike, before any repository file is sent.
		if code != exitcode.ModelOrSandbox || !strings.Contains(stderr, "model unfit (below_chance): 32 of 64") {
			t.Fatalf("repo %d: exit %d, stderr %q", i, code, stderr)
		}
		if calls := *calCalls - before; (i == 0) != (calls > 0) {
			t.Fatalf("repo %d: %d calibration calls; want a run only for the first repository", i, calls)
		}
	}
	if len(got) != len(repos) || m.calls != 0 {
		t.Fatalf("%d calibrations, %d scan calls", len(got), m.calls)
	}
	for i, c := range got[1:] {
		if !c.Cached || !reflect.DeepEqual(c.Result, got[0].Result) {
			t.Errorf("repo %d: calibration %+v, want the cached %+v", i+1, c.Result, got[0].Result)
		}
	}
}
