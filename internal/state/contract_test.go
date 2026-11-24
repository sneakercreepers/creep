package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestV1FixtureDecodes is the run-state contract fitness function (#8, #138):
// files written by v1 must decode in every later version. Each fixture line
// is decoded with unknown fields disallowed, so removing or renaming a field
// of Event or entry fails here, and so does retyping one; adding a field
// does not. Never edit the v1 fixtures: add a v2 directory instead.
func TestV1FixtureDecodes(t *testing.T) {
	tests := []struct {
		file string
		into func() any
	}{
		{"events.jsonl", func() any { return &Event{} }},
		{"events-resume.jsonl", func() any { return &Event{} }},
		{"cache-entry.json", func() any { return &entry{} }},
		{"calibration.json", func() any { return &calibrationEntry{} }},
	}
	for _, tt := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", "v1", tt.file))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			dec.DisallowUnknownFields()
			if err := dec.Decode(tt.into()); err != nil {
				t.Errorf("%s: %q no longer decodes strictly: %v", tt.file, sc.Text(), err)
			}
		}
	}
}

// The fixture must also mean the same thing: same kinds, outcomes and key
// semantics, not only the same field names.
func TestV1FixtureMeaning(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "v1", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sum, err := decodeEvents(f, testMAC, fixtureRunID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Mode != ModeReplay || len(sum.Steps) != 1 || sum.Steps[0] != "route:42" ||
		!sum.Ended || sum.Complete() || sum.Reason != "redact_run_full" {
		t.Fatalf("v1 events decode to %+v", sum)
	}

	checkResumeFixture(t)

	data, err := os.ReadFile(filepath.Join("testdata", "v1", "cache-entry.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := decodeEntry(data, testKey("x"), testMAC)
	if err != nil || string(resp) != "{\"finding\":1}\n" {
		t.Fatalf("v1 cache entry = %q, %v", resp, err)
	}
	if name := filepath.Base(testKey("x").fileName()); len(name) != 64+len(".json") {
		t.Fatalf("cache file name %q changed shape", name)
	}

	data, err = os.ReadFile(filepath.Join("testdata", "v1", "calibration.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := decodeCalibration(data, calKeyA, testMAC)
	if err != nil || !c.At.Equal(calAt) || string(c.Result) != `{"seed":1,"tier":"M"}` {
		t.Fatalf("v1 calibration = %+v, %v", c, err)
	}
}

// checkResumeFixture pins the fields ADR 0032 added to v1 (v0.4 review A2):
// the start line's header and a step's ms, which Summary.Elapsed reads.
func checkResumeFixture(t *testing.T) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "v1", "events-resume.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sum, err := decodeEvents(f, testMAC, fixtureRunID)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Mode != ModeLive || len(sum.Header) != 2 || sum.Header["version"] != strings.Repeat("a", 64) ||
		len(sum.Steps) != 3 || sum.Steps[1] != "tier:M" || sum.Elapsed != 16500*time.Millisecond || sum.Ended {
		t.Fatalf("v1 resume events decode to %+v", sum)
	}
}

const fixtureRunID = "20261113T120000Z-0123abcd"
