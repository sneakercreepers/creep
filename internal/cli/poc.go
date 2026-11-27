package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// pocPurpose labels PoC requests in egress.log.
const pocPurpose = "poc"

// maxPoCs bounds the findings one scan asks a PoC for: each costs a model
// call and verify.DefaultRuns runner containers.
const maxPoCs = 16

// pocInput is what the PoC stage needs from the scan: the tier its prompt
// is cut for, and the result whose probable findings it tries.
type pocInput struct {
	tier calibrate.Tier
	res  *scanResult
}

// errStopPoCs ends the PoC stage: the model or the sandbox cannot go on,
// so every PoC left is not run.
var errStopPoCs = errors.New("poc stage stopped")

// runPoCs starts the built app and runs a PoC for each probable finding
// of a class with a template (#25). A PoC that verified in at least one
// of its runs makes its finding verified with that rate and leaves a
// reproduction bundle; any other outcome leaves the finding probable.
func (s *session) runPoCs(ctx context.Context, w io.Writer, box appSandbox, app sandbox.App, in pocInput) report.Verification {
	todo := pocCandidates(in.res)
	if len(todo) == 0 {
		return report.Verification{Status: report.VerificationAppBuilt}
	}
	t, failed := startTarget(ctx, w, box, app)
	if failed != nil {
		return *failed
	}
	tier, err := pocTier(in.tier)
	if err != nil {
		return report.Verification{Status: report.VerificationAppBuilt, PoCs: report.PoCSummary{NotRun: len(todo)}}
	}
	st := pocStage{s: s, w: w, box: box, target: t, tier: tier, res: in.res, commit: headCommit(s.repo)}
	return report.Verification{Status: report.VerificationAppBuilt, PoCs: st.run(ctx, todo)}
}

// pocCandidates are the probable findings, in report order, whose class
// has a template and whose reader slice is known.
func pocCandidates(res *scanResult) []int {
	var out []int
	for i, f := range res.findings {
		if _, sliced := res.slices[i]; sliced && f.Status == report.StatusProbable && len(verify.TemplatesFor(f.Class)) > 0 {
			out = append(out, i)
		}
	}
	return out
}

func pocTier(t calibrate.Tier) (verify.Tier, error) {
	switch t {
	case calibrate.TierS:
		return verify.TierS, nil
	case calibrate.TierM:
		return verify.TierM, nil
	case calibrate.TierL:
		return verify.TierL, nil
	}
	return "", fmt.Errorf("tier %q: %w", string(t), errUnmapped)
}

// pocStage tries the PoCs of one scan against its started app.
type pocStage struct {
	s      *session
	w      io.Writer
	box    appSandbox
	target appTarget
	tier   verify.Tier
	res    *scanResult
	commit string
}

// pocBatch is the candidates one scan tries, the first maxPoCs in report
// order, and how many it leaves not run.
func pocBatch(todo []int) ([]int, int) {
	if len(todo) <= maxPoCs {
		return todo, 0
	}
	return todo[:maxPoCs], len(todo) - maxPoCs
}

func (st pocStage) run(ctx context.Context, candidates []int) report.PoCSummary {
	todo, skipped := pocBatch(candidates)
	sum := report.PoCSummary{NotRun: skipped}
	for i, at := range todo {
		if ctx.Err() != nil {
			sum.NotRun += len(todo) - i
			break
		}
		rate, err := st.tryOne(ctx, at)
		if err != nil {
			printError(st.w, "sandbox: no PoC run for "+st.res.findings[at].ID, err)
			sum.NotRun++
			if errors.Is(err, errStopPoCs) {
				sum.NotRun += len(todo) - i - 1
				break
			}
			continue
		}
		sum.Ran++
		switch {
		case rate.Intermittent():
			sum.Intermittent++
		case rate.Holds():
			sum.Verified++
		}
	}
	return sum
}

// tryOne asks the model for the finding's PoC, runs it DefaultRuns times
// and applies the rate. A rate of 0 changes nothing: no finding is ever
// verified by a PoC that never verified.
func (st pocStage) tryOne(ctx context.Context, at int) (verify.Rate, error) {
	f := &st.res.findings[at]
	p, err := askPoC(ctx, st.s.model, st.tier, f.Class, st.res.slices[at])
	if err != nil {
		return verify.Rate{}, err
	}
	rep, err := verify.Repeat(ctx, st.box, st.target.target, p, verify.DefaultRuns)
	if err != nil {
		return verify.Rate{}, fmt.Errorf("%w: %w", errStopPoCs, err)
	}
	fmt.Fprintf(st.w, "sandbox: PoC for %s (%s, %s) verified in %s runs\n", f.ID, f.Class, p.Template(), rep.Rate)
	if !rep.Rate.Holds() {
		return rep.Rate, nil
	}
	f.Status, f.Reason = report.StatusVerified, ""
	f.PoC = report.PoCRate{Verified: rep.Rate.Verified, Runs: rep.Rate.Runs}
	st.keepBundle(f, p, rep)
	return rep.Rate, nil
}

// keepBundle writes the finding's reproduction bundle; a bundle that
// cannot be made or written is named on stderr and changes no result.
func (st pocStage) keepBundle(f *report.Finding, p verify.PoC, rep verify.Repetition) {
	meta := verify.Meta{
		Finding: f.ID, Class: f.Class, Commit: st.commit,
		Images: st.target.images, Seed: st.target.seed, Target: st.target.target,
	}
	if err := writeBundle(st.s.store.Root(), meta, p, rep, st.s.red.File); err != nil {
		printError(st.w, "sandbox: no reproduction bundle for "+f.ID, err)
	}
}

// askPoC asks the model for a PoC of one probable finding, with the
// reader's slice (redact.File output only) as its code, through the same
// gateway, closed schema and strict decoding as the reader. The PoC must
// be one Build accepts, of a template that proves the finding's class.
// Invalid output skips this finding; anything else the model link
// returns (budget, transport) stops the stage.
func askPoC(ctx context.Context, model *models.HTTP, tier verify.Tier, class string, slice reader.Slice) (verify.PoC, error) {
	system, err := verify.System(tier)
	if err != nil {
		return verify.PoC{}, err
	}
	prompt, err := verify.UserPrompt(class, slice.Text)
	if err != nil {
		return verify.PoC{}, err
	}
	req, err := models.Complete[verify.Request](ctx, model, models.Request{
		Purpose: pocPurpose, System: system, Prompt: prompt, Redactions: slice.Redactions, Schema: verify.Schema(),
	})
	switch {
	case errors.Is(err, models.ErrInvalidOutput):
		return verify.PoC{}, fmt.Errorf("poc request: %w", err)
	case err != nil:
		return verify.PoC{}, fmt.Errorf("%w: poc request: %w", errStopPoCs, err)
	}
	p, err := verify.Build(req)
	if err != nil {
		return verify.PoC{}, err
	}
	if !verify.Fits(class, p) {
		return verify.PoC{}, fmt.Errorf("template %s does not prove %s: %w", p.Template(), class, verify.ErrInvalid)
	}
	return p, nil
}
