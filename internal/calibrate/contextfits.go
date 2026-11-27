package calibrate

import (
	"context"
	"fmt"

	"github.com/sneakercreepers/creep/internal/models"
)

// purposeDoctorContext labels creep doctor's context probe in egress.log.
const purposeDoctorContext = "doctor-context"

// MaxContextFitsBytes caps ContextFits' probe; the largest discovery call
// creep sends (tier L) fits under it.
const MaxContextFitsBytes = 144 << 10

// ContextFits sends one context probe of at least size bytes, built from
// opts.Seed with the needle on its first line, and returns "" when the
// model found it, else why not. An endpoint that cuts the start of a long
// input loses the needle, as it would lose a scan's system prompt. A
// refusal for the size is a result; any other failure is returned. creep
// doctor runs it at the size of a tier's largest discovery call (#362).
func ContextFits(ctx context.Context, opts Options, size int) (ContextStop, error) {
	if opts.Model == nil || opts.Redactor == nil || size < 1 || size > MaxContextFitsBytes {
		return "", fmt.Errorf("%w: ContextFits needs a Model, a Redactor and a size of 1-%d bytes", ErrOptions, MaxContextFitsBytes)
	}
	p := newLeadingProbe(probeSource(opts.Seed), size)
	req, err := newRequest(opts.Redactor, purposeDoctorContext, contextSystem, p.prompt)
	if err != nil {
		return "", fmt.Errorf("doctor context probe: %w", err)
	}
	req.Schema, req.Grammar = contextSchema(), contextGrammar()
	a, err := models.Complete[contextAnswer](ctx, opts.Model, req)
	stop, _, sized := sizeRefusal(err)
	switch {
	case err != nil && !sized:
		return "", fmt.Errorf("doctor context probe: %w", err)
	case err == nil && a.Value != p.value:
		return ContextStopWrongAnswer, nil
	}
	return stop, nil
}
