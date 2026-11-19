package sandbox

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestRunRefusesImageVolumes is the protection test for image volumes: an
// image that declares a VOLUME, or whose answer cannot be read, starts no
// container; only a JSON null or empty object lets the run go ahead.
func TestRunRefusesImageVolumes(t *testing.T) {
	tests := []struct {
		name   string
		answer cliResult
		want   error // nil: the container runs
	}{
		{"one volume", cliResult{stdout: []byte(`{"/data":{}}` + "\n")}, ErrImageVolumes},
		{"many volumes", cliResult{stdout: []byte(`{"/a":{},"/b":{},"/var/lib/db":{}}`)}, ErrImageVolumes},
		{"inspect failed", cliResult{exit: 1}, ErrStart},
		{"empty answer", cliResult{}, ErrStart},
		{"not JSON", cliResult{stdout: []byte("<no value>")}, ErrStart},
		{"a list, not an object", cliResult{stdout: []byte(`["/data"]`)}, ErrStart},
		{"truncated", cliResult{stdout: []byte("null"), truncated: true}, ErrStart},
		{"no volumes (null)", cliResult{stdout: []byte("null\n")}, nil},
		{"no volumes ({})", cliResult{stdout: []byte("{}")}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{image: &tt.answer}
			s := testSandbox(t, rec)
			_, err := s.Run(context.Background(), Spec{Image: testImage})
			ran := len(rec.to("run")) == 1
			switch {
			case tt.want == nil && (err != nil || !ran):
				t.Fatalf("err %v, ran %v", err, ran)
			case tt.want != nil && (!errors.Is(err, tt.want) || ran):
				t.Fatalf("err %v (want %v), ran %v", err, tt.want, ran)
			}
			inspect := rec.to("image")
			if len(inspect) != 1 || !slices.Contains(inspect[0], testImage) || inspect[0][0] != "--host="+usableDocker().Host {
				t.Errorf("inspect calls %q", inspect)
			}
		})
	}
}
