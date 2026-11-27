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

// classTasks is how many tasks Generate gives each class, for every seed:
// 64 of them in the planned classes.
var classTasks = map[Class]int{
	ClassSQLi: 14, ClassNoSQLInjection: 8, ClassCommandInjection: 14, ClassPathTraversal: 14,
	ClassSSRF: 14, ClassIDOR: 14, ClassMissingAuth: 14, ClassPrototypePollution: 8,
}

// perfectResult is a full-marks calibration over 100 tasks, half of each
// class's tasks safe twins.
func perfectResult() Result {
	r := Result{
		Structured: newStructuredCheck(100, 0),
		Tools:      newToolCheck(3, 3),
		Context:    ContextCheck{EffectiveBytes: 128 << 10},
		Overall:    newScore(100, 100),
	}
	for _, c := range Classes() {
		n := classTasks[c]
		r.Classes = append(r.Classes, ClassScore{Class: c, Score: newScore(n, n), SafeTwins: n / 2})
	}
	return r
}

// missVulnerable takes wrong answers off the vulnerable tasks of classes,
// by index into Classes().
func missVulnerable(r *Result, wrong map[int]int) {
	for i, n := range wrong {
		c := &r.Classes[i]
		c.Score = newScore(c.Correct-n, c.Total)
	}
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
		// The overall bound is over the 64 planned tasks: L needs 55, M 44.
		{"planned overall at L floor", func(r *Result) { missVulnerable(r, map[int]int{0: 3, 2: 3, 3: 3}) }, TierL},
		{"planned overall under L floor", func(r *Result) { missVulnerable(r, map[int]int{0: 3, 2: 3, 3: 3, 4: 1}) }, TierM},
		{"planned overall at M floor", func(r *Result) { missVulnerable(r, map[int]int{0: 7, 2: 7, 3: 6}) }, TierM},
		{"planned overall under M floor", func(r *Result) { missVulnerable(r, map[int]int{0: 7, 2: 7, 3: 7}) }, TierS},
		// #363: classes the planner cannot plan neither lower nor lift a tier,
		// and the all-tasks score is reported, not gated on.
		{"unplanned classes all wrong", func(r *Result) { missVulnerable(r, map[int]int{5: 7, 6: 7, 7: 4}) }, TierL},
		{"unplanned class not measured", func(r *Result) { r.Classes[7].Score = newScore(0, 0) }, TierL},
		{"all-tasks overall is not read", func(r *Result) { r.Overall = newScore(0, 100) }, TierL},
		{"duplicated class", func(r *Result) { r.Classes[7] = r.Classes[0] }, TierS},
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

// tierConsts finds both spellings of a Tier value, `X Tier = "x"` and
// `X = Tier("x")`. A Tier whose value is anything but a string literal
// fails the test rather than being skipped.
func tierConsts(t *testing.T, f *ast.File) []Tier {
	t.Helper()
	var tiers []Tier
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		typed := isTier(spec.Type)
		if typed && len(spec.Values) != len(spec.Names) {
			t.Fatalf("Tier %s without a literal value", spec.Names[0])
		}
		for _, v := range spec.Values {
			converted := false
			if call, ok := v.(*ast.CallExpr); ok && isTier(call.Fun) && len(call.Args) == 1 {
				v, converted = call.Args[0], true
			}
			if typed || converted {
				tiers = append(tiers, tierLiteral(t, v))
			}
		}
		return true
	})
	return tiers
}

func tierLiteral(t *testing.T, v ast.Expr) Tier {
	t.Helper()
	lit, ok := v.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		t.Fatalf("Tier with a non-literal value at %v", v.Pos())
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		t.Fatal(err)
	}
	return Tier(s)
}

func isTier(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "Tier"
}
