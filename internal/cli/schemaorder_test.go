package cli

import (
	"encoding/json"
	"testing"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/verify"
)

// Acceptance (#362): no schema a scan sends (discovery, reader, PoC) has a
// property out of reasoning order, so none has "end" before "start";
// calibrate checks its own schemas, and models.Complete refuses any other.
func TestScanSchemasInReasoningOrder(t *testing.T) {
	for name, schema := range map[string]json.RawMessage{
		"discover": discover.Schema(), "reader": reader.Schema(), "poc": verify.Schema(),
	} {
		if err := models.CheckPropertyOrder(schema); err != nil {
			t.Errorf("%s schema: %v", name, err)
		}
	}
}
