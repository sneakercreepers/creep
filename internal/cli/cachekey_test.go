package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/state"
)

// Pentest P8: a recording made against one endpoint is never the answer for
// another with the same model name, and any endpoint makes a valid key.
func TestCacheKeyBindsEndpoint(t *testing.T) {
	call := func(endpoint string) gateway.Call {
		return gateway.Call{Endpoint: endpoint, Model: "command", Purpose: "reader", Payload: []byte("{}")}
	}
	a, b := cacheKey(call("command://claude-0123456789abcdef")), cacheKey(call("command://codex-0123456789abcdef"))
	if a == b {
		t.Fatalf("two endpoints share the key %+v", a)
	}
	if again := cacheKey(call("command://claude-0123456789abcdef")); again != a {
		t.Fatalf("same call, different keys: %+v %+v", a, again)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), ".creep"), make([]byte, state.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	long := "https://models.example/v1/x?key=a+b%20c&" + strings.Repeat("p", 300)
	if _, _, err := store.Lookup(cacheKey(call(long))); err != nil {
		t.Fatalf("key for %d-byte endpoint: %v", len(long), err)
	}
}
