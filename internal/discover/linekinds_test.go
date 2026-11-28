package discover

import (
	"slices"
	"strings"
	"testing"
)

// SinkKindsOn reads the tripwire table as a scan does: word-bounded calls,
// one kind per kind found, only the first line.
func TestSinkKindsOn(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []SinkKind
	}{
		{"code eval", "    return str(eval(expr))", []SinkKind{SinkCodeEval}},
		{"eval with a blank before the call", "x = eval (expr)", []SinkKind{SinkCodeEval}},
		{"deserialization", "    obj = pickle.loads(data)", []SinkKind{SinkDeserialize}},
		{"shell", `    os.system("ping " + host)`, []SinkKind{SinkShell}},
		{"two kinds, once each", "os.system(eval(a)); os.system(eval(b))", []SinkKind{SinkShell, SinkCodeEval}},
		{"identifier before the call is not the call", "    return str(ast.literal_eval(expr))", nil},
		{"no sink", "    return \"ok\"", nil},
		{"empty", "", nil},
		{"only the first line", "x = 1\neval(expr)", nil},
		{"long line", strings.Repeat("a", 1<<16) + " eval(x)", []SinkKind{SinkCodeEval}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SinkKindsOn(tt.line)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("SinkKindsOn = %v, want %v", got, tt.want)
			}
		})
	}
}
