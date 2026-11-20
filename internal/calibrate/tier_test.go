package calibrate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// perfectResult is a full-marks calibration over 100 tasks.
func perfectResult() Result {
	r := Result{
		Structured: newStructuredCheck(100, 0),
		Tools:      newToolCheck(3, 3),
		Context:    ContextCheck{EffectiveBytes: 128 << 10},
		Overall:    newScore(100, 100),
	}
	for _, c := range Classes() {
		r.Classes = append(r.Classes, ClassScore{Class: c, Score: newScore(12, 12)})
	}
	return r
}

func TestAssignTier(t *testing.T) {
	tests := []struct {
		name string
		edit func(r *Result)
		want Tier
	}{
		{"perfect", func(*Result) {}, TierL},
		{"5% invalid is the limit", func(r *Result) { r.Structured = newStructuredCheck(100, 5) }, TierL},
		{"6% invalid", func(r *Result) { r.Structured = newStructuredCheck(100, 6) }, TierS},
		{"context exactly 128 KiB", func(r *Result) { r.Context.EffectiveBytes = 128 << 10 }, TierL},
		{"context just under 128 KiB", func(r *Result) { r.Context.EffectiveBytes = 128<<10 - 1 }, TierM},
		{"context exactly 32 KiB", func(r *Result) { r.Context.EffectiveBytes = 32 << 10 }, TierM},
		{"context just under 32 KiB", func(r *Result) { r.Context.EffectiveBytes = 32<<10 - 1 }, TierS},
		{"one tool probe wrong", func(r *Result) { r.Tools = newToolCheck(3, 2) }, TierM},
		{"no tool probes", func(r *Result) { r.Tools = newToolCheck(0, 0) }, TierM},
		{"class at L floor", func(r *Result) { r.Classes[0].Score = newScore(11, 14) }, TierL},
		{"class just under L floor", func(r *Result) { r.Classes[0].Score = newScore(10, 14) }, TierM},
		{"class at M floor", func(r *Result) { r.Classes[0].Score = newScore(7, 14) }, TierM},
		{"class just under M floor", func(r *Result) { r.Classes[0].Score = newScore(6, 14) }, TierS},
		{"class not measured", func(r *Result) { r.Classes[3].Score = newScore(0, 0) }, TierS},
		{"class missing", func(r *Result) { r.Classes = r.Classes[1:] }, TierS},
		{"overall at L floor", func(r *Result) { r.Overall = newScore(84, 100) }, TierL},
		{"overall under L floor", func(r *Result) { r.Overall = newScore(83, 100) }, TierM},
		{"overall at M floor", func(r *Result) { r.Overall = newScore(65, 100) }, TierM},
		{"overall under M floor", func(r *Result) { r.Overall = newScore(64, 100) }, TierS},
		{"zero tasks", func(r *Result) { *r = Result{} }, TierS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := perfectResult()
			tt.edit(&r)
			if got := assignTier(r); got != tt.want {
				t.Errorf("tier = %s, want %s", got, tt.want)
			}
		})
	}
}

// Every Tier constant declared in this package is one assignTier can
// return, so Tiers() is complete and a mapping test built on it (the CLI's
// TestTierMappingIsExhaustive) fails when a tier is added without a mapping.
func TestTiersListsEveryDeclaredTier(t *testing.T) {
	listed := map[Tier]bool{}
	for _, tier := range Tiers() {
		if listed[tier] {
			t.Errorf("tier %s listed twice", tier)
		}
		listed[tier] = true
	}
	declared := declaredTiers(t)
	for _, tier := range declared {
		if !listed[tier] {
			t.Errorf("tier %s is declared but no tier rule returns it", tier)
		}
	}
	if len(declared) != len(listed) {
		t.Errorf("declared tiers %v, Tiers() %v", declared, Tiers())
	}
}

// declaredTiers reads the value of every constant of type Tier in the
// package's non-test sources.
func declaredTiers(t *testing.T) []Tier {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var tiers []Tier
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		tiers = append(tiers, tierConsts(t, f)...)
	}
	return tiers
}

func tierConsts(t *testing.T, f *ast.File) []Tier {
	t.Helper()
	var tiers []Tier
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || !isTierType(spec.Type) {
			return true
		}
		for _, v := range spec.Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok {
				t.Fatalf("tier constant with a non-literal value at %v", v.Pos())
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			tiers = append(tiers, Tier(s))
		}
		return true
	})
	return tiers
}

func isTierType(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "Tier"
}
