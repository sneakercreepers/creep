package sandbox

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestAppPort: the lowest declared TCP port of an image this sandbox
// built, 0 when it declares none; any other image is refused before the
// runtime is asked, and an answer that is not a port map is an error.
func TestAppPort(t *testing.T) {
	app := App{Image: "sha256:" + fakeID}
	tests := []struct {
		name   string
		answer cliResult
		want   int
		err    error
	}{
		{"one port", cliResult{stdout: []byte(`{"8080/tcp":{}}` + "\n")}, 8080, nil},
		{"lowest of two", cliResult{stdout: []byte(`{"5000/tcp":{},"80/tcp":{}}`)}, 80, nil},
		{"udp only", cliResult{stdout: []byte(`{"53/udp":{}}`)}, 0, nil},
		{"none", cliResult{stdout: []byte("null\n")}, 0, nil},
		{"odd keys", cliResult{stdout: []byte(`{"x/tcp":{},"70000/tcp":{},"0/tcp":{},"+80/tcp":{},"/tcp":{},"8080":{},"9090/tcp":{}}`)}, 9090, nil},
		{"not a map", cliResult{stdout: []byte(`["8080/tcp"]`)}, 0, ErrStart},
		{"inspect fails", cliResult{exit: 1}, 0, ErrStart},
		{"truncated", cliResult{stdout: []byte(`{"80/tcp":{}}`), truncated: true}, 0, ErrStart},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{images: map[string]cliResult{app.Image: tt.answer}}
			s := testSandbox(t, rec)
			s.recordImage(app.Image)
			got, err := s.AppPort(context.Background(), app)
			if got != tt.want || !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) {
				t.Errorf("AppPort = %d, %v; want %d, %v", got, err, tt.want, tt.err)
			}
			inspect := rec.to("image")
			if len(inspect) != 1 || !slices.Contains(inspect[0], "{{json .Config.ExposedPorts}}") {
				t.Errorf("calls %q", inspect)
			}
		})
	}
	rec := &recorder{}
	s := testSandbox(t, rec)
	for _, other := range []App{{Image: "sha256:" + fakeID}, {}, {Image: "sha256:" + fakeID, Unavailable: BuildFailed}} {
		if _, err := s.AppPort(context.Background(), other); !errors.Is(err, ErrSpec) {
			t.Errorf("%+v: %v, want ErrSpec", other, err)
		}
	}
	if len(rec.to("image")) != 0 {
		t.Errorf("an image this sandbox did not build was inspected: %q", rec.calls)
	}
}
