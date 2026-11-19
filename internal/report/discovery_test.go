package report

import (
	"bytes"
	"strings"
	"testing"
)

// ADR 0017 D3: the inventory, the whole-file count and each failed batch's
// cause are in Markdown, never in JSON v1, so the JSON stays the contract
// and a missed canary is never read as a syntax error.
func TestDiscoveryInMarkdownOnly(t *testing.T) {
	in := sampleInput(t, true)
	in.Discovery = Discovery{
		WholeFiles: 7,
		Inventory:  []InventoryCount{{Kind: InventoryLanguage, ID: "go", Files: 5}, {Kind: InventoryManifest, ID: "gomod", Files: 1}},
		Batches:    []BatchNote{{Batch: 2, Files: 3, Cause: CauseCanaryMissed}, {Batch: 4, Files: 1, Cause: CauseInvalidReply}},
	}
	out := render(t, newTestReport(t, in))
	md := string(out["md"])
	for _, want := range []string{
		"Discovery sent 7 whole source files, each redacted",
		"language `go` 5, manifest `gomod` 1",
		"discovery canary not found in batch 2: the model did not follow the instructions for this batch (3 files)",
		"discovery reply invalid for batch 4",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown lacks %q:\n%s", want, md)
		}
	}
	for _, leak := range []string{"gomod", "canary", "whole"} {
		if bytes.Contains(out["json"], []byte(leak)) || bytes.Contains(out["sarif"], []byte(leak)) {
			t.Errorf("JSON or SARIF carries %q", leak)
		}
	}
	plain := string(render(t, newTestReport(t, sampleInput(t, true)))["md"])
	if strings.Contains(plain, "## Inventory") || strings.Contains(plain, "whole source files") {
		t.Errorf("Markdown names discovery for a report without it:\n%s", plain)
	}
}
