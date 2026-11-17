package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// ReadJSON is what `creep why` trusts: a report WriteJSON wrote reads back
// the same, and anything edited, planted or truncated fails as ErrInvalid.
func TestReadJSON(t *testing.T) {
	var good bytes.Buffer
	if err := WriteJSON(&good, newTestReport(t, sampleInput(t, true))); err != nil {
		t.Fatal(err)
	}
	r, err := ReadJSON(bytes.NewReader(good.Bytes()))
	if err != nil {
		t.Fatalf("ReadJSON(WriteJSON output) = %v", err)
	}
	f, ok := r.Finding("f1")
	if !ok || f.Confidence != 90 || len(f.Evidence) != 1 || f.Evidence[0] != (LineRange{10, 12}) {
		t.Fatalf("Finding(f1) = %+v, %v", f, ok)
	}
	if _, ok := r.Finding("nope"); ok {
		t.Fatal("Finding(nope) found a finding")
	}
	text := good.String()
	tests := []struct {
		name string
		in   string
	}{
		{"unknown field", strings.Replace(text, `"schema_version"`, `"extra":1,"schema_version"`, 1)},
		{"trailing value", text + "{}"},
		{"other version", strings.Replace(text, `"schema_version": 1`, `"schema_version": 2`, 1)},
		{"finding with free-text ID", strings.Replace(text, `"id": "f1"`, `"id": "f1 \u001b[2J"`, 1)},
		{"unknown status", strings.Replace(text, `"status": "verified"`, `"status": "fixed"`, 1)},
		{"path outside the repository", strings.Replace(text, `"path": "app/db.py"`, `"path": "../../etc/passwd"`, 1)},
		{"truncated", text[:len(text)/2]},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.in == text {
				t.Fatal("test input was not changed")
			}
			if _, err := ReadJSON(strings.NewReader(tt.in)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ReadJSON = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReadJSONRefusesOversize(t *testing.T) {
	big := bytes.Repeat([]byte(" "), maxReportBytes+1)
	if _, err := ReadJSON(bytes.NewReader(big)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReadJSON(oversize) = %v, want ErrInvalid", err)
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{
		"sink-1": true, "f1": true, "": false, "-x": false, "a b": false,
		"a\x1b": false, strings.Repeat("a", 129): false, "../etc": false,
	} {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}
