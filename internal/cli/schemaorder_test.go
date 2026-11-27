package cli

import (
	"encoding/json"
	"regexp"
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/verify"
)

var requiredArray = regexp.MustCompile(`"required":\[[^\]]*\]`)

// Acceptance (#362): no schema a scan sends (discovery, reader, PoC) has a
// property out of reasoning order, so none has "end" before "start".
// CheckPropertyOrder ties every object's properties to its required array;
// the arrays themselves are pinned here, in the order the schema writes
// them, so a reordered required list fails too. calibrate pins its own.
func TestScanSchemasInReasoningOrder(t *testing.T) {
	tests := []struct {
		name   string
		schema json.RawMessage
		want   []string
	}{
		{"discover", discover.Schema(), []string{
			`"required":["file","start","end","kind"]`,
			`"required":["file","line","kind","entry"]`,
			`"required":["file","start","end"]`,
			`"required":["entries","sinks","auth"]`,
		}},
		{"reader", reader.Schema(), []string{
			`"required":["start","end"]`,
			`"required":["verdict","evidence","confidence"]`,
		}},
		{"poc", verify.Schema(), []string{
			`"required":["request","oracle"]`,
			`"required":["auth","session","token_field","request","oracle"]`,
			`"required":["request","context","technique"]`,
			`"required":["request","style","depth"]`,
			`"required":["template","http_request","http_sequence","sql_payload","path_payload"]`,
			`"required":["name","value"]`,
			`"required":["method","path","headers","content_type","body"]`,
			`"required":["kind","status"]`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := models.CheckPropertyOrder(tt.schema); err != nil {
				t.Fatalf("%s schema: %v", tt.name, err)
			}
			var got []string
			for _, m := range requiredArray.FindAll(tt.schema, -1) {
				got = append(got, string(m))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("%s required arrays\n got %q\nwant %q", tt.name, got, tt.want)
			}
		})
	}
}
