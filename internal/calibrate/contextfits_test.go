package calibrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// ContextFits (#362) finds an endpoint that cuts the start of a long
// input: the needle is on the first line, so a model that only saw the end
// answers wrong. A size refusal is a result; a transport failure is an
// error; a size out of range is refused before anything is sent.
func TestContextFits(t *testing.T) {
	needle := func(user string) string {
		m := needlePattern.FindStringSubmatch(user)
		if m == nil {
			return `{"value":"none"}`
		}
		return `{"value":"` + m[2] + `"}`
	}
	tests := []struct {
		name    string
		send    models.SendFunc
		size    int
		want    ContextStop
		wantErr error
	}{
		{"full input", answering(needle).send, 16 << 10, "", nil},
		{"start cut off", answering(func(user string) string { return needle(user[len(user)/2:]) }).send, 16 << 10, ContextStopWrongAnswer, nil},
		{"invalid reply", answering(func(string) string { return "not json" }).send, 16 << 10, ContextStopInvalidOutput, nil},
		{"refused for size", func(context.Context, gateway.Call) (*gateway.Reply, error) {
			return &gateway.Reply{Status: 413, Body: []byte(`{}`)}, nil
		}, 16 << 10, ContextStopStatus, nil},
		{"unreachable", contextSend, 16 << 10, "", errors.New("send")},
		{"size zero", answering(needle).send, 0, "", ErrOptions},
		{"size over the cap", answering(needle).send, MaxContextFitsBytes + 1, "", ErrOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sent []gateway.Call
			send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
				sent = append(sent, c)
				return tt.send(ctx, c)
			}
			got, err := ContextFits(context.Background(), testOptions(t, 7, send), tt.size)
			switch {
			case tt.wantErr == ErrOptions:
				if !errors.Is(err, ErrOptions) || len(sent) != 0 {
					t.Fatalf("ContextFits = %v after %d sends, want ErrOptions and none", err, len(sent))
				}
				return
			case tt.wantErr != nil:
				if err == nil {
					t.Fatal("ContextFits succeeded on a failing transport")
				}
				return
			case err != nil || got != tt.want:
				t.Fatalf("ContextFits = %q, %v; want %q", got, err, tt.want)
			}
			if len(userTurn(sent[0].Payload)) < tt.size || sent[0].Purpose != purposeDoctorContext {
				t.Errorf("probe of %d bytes, purpose %q; want at least %d, %q", len(userTurn(sent[0].Payload)), sent[0].Purpose, tt.size, purposeDoctorContext)
			}
		})
	}
}

// The needle opens the doctor's probe and is in no filler line.
func TestLeadingProbePlacesNeedleFirst(t *testing.T) {
	p := newLeadingProbe(probeSource(3), 8<<10)
	first, _, _ := strings.Cut(p.prompt, "\n")
	if !strings.Contains(first, `"`+p.value+`"`) || strings.Count(p.prompt, p.value) != 1 || len(p.prompt) < 8<<10 {
		t.Errorf("first line %q, value %q appears %d times", first, p.value, strings.Count(p.prompt, p.value))
	}
}
