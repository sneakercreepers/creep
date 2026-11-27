package recipe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/reader"
)

// TestEarlierRecipesLoadUnchanged is acceptance criterion 2 of #371: the
// two classes are added to v1, so every recipe written before them,
// including a command_injection recipe for an eval sink, parses and loads
// byte for byte as it is, with its class unchanged.
func TestEarlierRecipesLoadUnchanged(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "v1", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no committed v1 recipes: %v", err)
	}
	recipes := map[string][]byte{"template": Template()}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		recipes[filepath.Base(f)] = data
	}
	for name, data := range recipes {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(data, acceptPoC)
			if err != nil {
				t.Fatalf("an earlier recipe is refused: %v", err)
			}
			m := &fakeModel{verdict: map[int]string{parsed.Fixtures.Vulnerable.SinkLine: "vulnerable"}}
			r, _, err := checker(t, m, reader.TierM).Load(context.Background(), data, acceptPoC)
			if err != nil || r.Class != parsed.Class {
				t.Fatalf("Load = %v, %v", r, err)
			}
			if !strings.Contains(string(m.calls[0].Payload), "HYPOTHESIS: "+parsed.Class+",") {
				t.Errorf("reader call does not name class %s", parsed.Class)
			}
		})
	}
}

// TestSplitClassRecipesLoad is acceptance criterion 1 of #371: a
// code_injection or insecure_deserialization recipe loads only when its
// fixtures pass, its hint reaches reader calls for its class as "~ " lines
// of the HINT block, and HintFor gives it to a finding of that class and to
// no command_injection finding.
func TestSplitClassRecipesLoad(t *testing.T) {
	tests := []struct {
		file   string
		class  reader.Class
		canary string
	}{
		{"python-eval-request.json", reader.ClassCodeInjection, "QX7EVALHINT"},
		{"python-pickle-body.json", reader.ClassDeserialization, "QX7PICKLEHINT"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(data, acceptPoC)
			if err != nil {
				t.Fatal(err)
			}
			sink := parsed.Fixtures.Vulnerable.SinkLine
			m := &fakeModel{verdict: map[int]string{sink: "vulnerable"}}
			r, _, err := checker(t, m, reader.TierM).Load(context.Background(), data, acceptPoC)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			checkHintSent(t, m, tt.class, tt.canary, r.ID)
			if got := HintFor([]*Recipe{r}, tt.class, "app/calc.py"); got != r.Hint {
				t.Errorf("HintFor(%v) = %q, want the recipe's hint", tt.class, got)
			}
			if got := HintFor([]*Recipe{r}, reader.ClassCommandInjection, "app/calc.py"); got != "" {
				t.Errorf("a command_injection finding got the %v hint", tt.class)
			}
			wrong := &fakeModel{verdict: map[int]string{}}
			if _, _, err := checker(t, wrong, reader.TierM).Load(context.Background(), data, acceptPoC); !errors.Is(err, ErrFixtures) {
				t.Errorf("unflagged vulnerable fixture: Load = %v, want ErrFixtures", err)
			}
		})
	}
}

// checkHintSent checks both reader calls name class and carry the hint
// canary, and only inside the HINT block.
func checkHintSent(t *testing.T, m *fakeModel, class reader.Class, canary, id string) {
	t.Helper()
	if len(m.calls) != 2 {
		t.Fatalf("%d model calls, want 2", len(m.calls))
	}
	for i, c := range m.calls {
		_, user, err := messages(c.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(user, "HYPOTHESIS: "+class.String()+",") || !strings.Contains(user, "\nHINT (") || !strings.Contains(user, canary) {
			t.Errorf("call %d: no %s hypothesis with its HINT block", i+1, class)
		}
	}
	if err := hintOnlyInReader(m.calls, canary, id); err != nil {
		t.Error(err)
	}
}
