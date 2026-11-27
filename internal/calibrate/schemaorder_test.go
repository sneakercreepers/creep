package calibrate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/models"
)

// Acceptance (#362): every calibration schema lists its properties in the
// order its required array gives, the order a constrained decoder makes
// the model write them, and that order is pinned here.
func TestSchemaPropertyOrder(t *testing.T) {
	tests := []struct {
		name   string
		schema json.RawMessage
		want   string
	}{
		{"task", taskSchema(), `"required":["vulnerable","class","line"]`},
		{"tool", toolSchema(), `"required":["tool","argument"]`},
		{"context", contextSchema(), `"required":["value"]`},
	}
	for _, tt := range tests {
		if err := models.CheckPropertyOrder(tt.schema); err != nil {
			t.Errorf("%s schema: %v", tt.name, err)
		}
		if strings.Count(string(tt.schema), `"required":`) != 1 || !strings.Contains(string(tt.schema), tt.want) {
			t.Errorf("%s schema %s: want its one required array to be %s", tt.name, tt.schema, tt.want)
		}
	}
}
