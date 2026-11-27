package calibrate

import (
	"encoding/json"
	"testing"

	"github.com/sneakercreepers/creep/internal/models"
)

// Acceptance (#362): every calibration schema lists its properties in the
// order its required array gives, the order a constrained decoder makes
// the model write them.
func TestSchemaPropertyOrder(t *testing.T) {
	for name, schema := range map[string]json.RawMessage{"task": taskSchema(), "tool": toolSchema(), "context": contextSchema()} {
		if err := models.CheckPropertyOrder(schema); err != nil {
			t.Errorf("%s schema: %v", name, err)
		}
	}
}
