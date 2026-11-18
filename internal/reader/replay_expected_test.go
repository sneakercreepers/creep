package reader

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readerClass maps expected.json classes to the reader's. The apps' other
// classes have no reader class, so no hypothesis is built for them.
var readerClass = map[string]Class{
	"sqli":              ClassSQLInjection,
	"command_injection": ClassCommandInjection,
	"path_traversal":    ClassPathTraversal,
	"ssrf":              ClassSSRF,
	"nosql_injection":   ClassNoSQLInjection,
}

var unreadClasses = map[string]bool{
	"idor": true, "missing_auth": true, "prototype_pollution": true,
}

type expectedFinding struct {
	Class string `json:"class"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Route string `json:"route"`
}

type expectedApp struct {
	App        string            `json:"app"`
	Vulnerable []expectedFinding `json:"vulnerable"`
}

// mismatches lists how got differs from the verdicts expected.json implies.
func (c appCase) mismatches(variant string, got map[HypothesisID]Signal) []error {
	_, byID := c.targets(variant)
	var errs []error
	if len(got) != len(byID) {
		errs = append(errs, fmt.Errorf("%d signals for %d hypotheses", len(got), len(byID)))
	}
	for id, h := range byID {
		sig, ok := got[id]
		if !ok {
			errs = append(errs, fmt.Errorf("hypothesis %d: no signal", id))
			continue
		}
		if err := h.check(sig); err != nil {
			errs = append(errs, fmt.Errorf("hypothesis %d (%s, sink line %d): %w", id, h.class, h.sink, err))
		}
	}
	return errs
}

// check accepts a vulnerable verdict citing the sink on the vulnerable
// variant and a not_vulnerable verdict on the safe twin.
func (h appHypothesis) check(sig Signal) error {
	want := VerdictNotVulnerable
	if h.variant == variantVulnerable {
		want = VerdictVulnerable
	}
	if sig.Verdict != want {
		return fmt.Errorf("verdict %d, want %d", sig.Verdict, want)
	}
	sink := LineRange{Start: uint32(h.sink), End: uint32(h.sink)} //nolint:gosec // G115: app lines are small
	if want == VerdictVulnerable && !within(sink, sig.Evidence) {
		return errors.New("evidence does not cite the sink line")
	}
	return nil
}

// checkAgainstApp reports every expected.json finding of a reader class
// without a hypothesis, every vulnerable hypothesis expected.json does not
// list, every hypothesis without a twin, and every route or line that is
// not where the case says.
func (c appCase) checkAgainstApp() []error {
	exp, err := readExpected(c.app)
	if err != nil {
		return []error{err}
	}
	var errs []error
	for _, f := range exp.Vulnerable {
		if err := c.covers(f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, h := range c.hyps {
		if h.variant == variantVulnerable && !listed(h, c.file, exp.Vulnerable) {
			errs = append(errs, fmt.Errorf("vulnerable %s at line %d is not in expected.json", h.class, h.sink))
		}
		if !c.hasTwin(h) {
			errs = append(errs, fmt.Errorf("%s %s on %s has no twin", h.variant, h.class, h.route))
		}
		if err := c.checkLines(h); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func readExpected(app string) (expectedApp, error) {
	var exp expectedApp
	data, err := os.ReadFile(filepath.Join(appsDir, app, "expected.json"))
	if err != nil {
		return exp, err
	}
	if err := json.Unmarshal(data, &exp); err != nil {
		return exp, fmt.Errorf("expected.json: %w", err)
	}
	if exp.App != app {
		return exp, fmt.Errorf("expected.json names app %q", exp.App)
	}
	return exp, nil
}

func (c appCase) covers(f expectedFinding) error {
	if _, ok := readerClass[f.Class]; !ok {
		if unreadClasses[f.Class] {
			return nil
		}
		return fmt.Errorf("expected class %q has no reader mapping: add it to readerClass or unreadClasses", f.Class)
	}
	for _, h := range c.hyps {
		if h.variant == variantVulnerable && listed(h, c.file, []expectedFinding{f}) {
			return nil
		}
	}
	return fmt.Errorf("no hypothesis for expected %s at %s:%d", f.Class, f.File, f.Line)
}

func listed(h appHypothesis, file string, findings []expectedFinding) bool {
	for _, f := range findings {
		if readerClass[f.Class] == h.class && f.File == file && f.Line == h.sink && f.Route == h.route {
			return true
		}
	}
	return false
}

func (c appCase) hasTwin(h appHypothesis) bool {
	for _, o := range c.hyps {
		if o.variant != h.variant && o.class == h.class && o.route == h.route {
			return true
		}
	}
	return false
}

// checkLines requires the quoted route on the source line or the line above
// it (the decorator), and both lines inside the file.
func (c appCase) checkLines(h appHypothesis) error {
	data, err := os.ReadFile(filepath.Join(appsDir, c.app, h.variant, c.file))
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	if h.source < 2 || h.source > len(lines) || h.sink < 1 || h.sink > len(lines) {
		return fmt.Errorf("%s lines %d, %d are outside %s", h.variant, h.source, h.sink, c.file)
	}
	quoted := `"` + h.route + `"`
	if !strings.Contains(lines[h.source-1], quoted) && !strings.Contains(lines[h.source-2], quoted) {
		return fmt.Errorf("%s: route %s is not at line %d", h.variant, h.route, h.source)
	}
	return nil
}
