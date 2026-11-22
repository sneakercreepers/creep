package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Header bytes are not in the payload file, its sha256 or the redaction
// counts, so a header outside allowedHeaders, or header values over
// maxHeaderBytes, are refused before anything is written or sent (#115).
// The known names pass in any case.
func TestUnknownHeaderRefused(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		sent   bool
	}{
		{"repository text in a custom header", http.Header{"X-Context": {"func main() {}"}}, false},
		{"host override", http.Header{"Host": {"evil.example"}}, false},
		{"lowercase unknown", http.Header{"x-forwarded-for": {"10.0.0.1"}}, false},
		{"oversized credential", http.Header{"Authorization": {"Bearer " + strings.Repeat("k", maxHeaderBytes)}}, false},
		{"values add up", http.Header{"X-Api-Key": {strings.Repeat("k", maxHeaderBytes/2)}, "Authorization": {strings.Repeat("k", maxHeaderBytes/2+1)}}, false},
		{"known names", http.Header{"Content-Type": {"application/json"}, "Anthropic-Version": {"2023-06-01"}, "X-Api-Key": {"k"}, "Accept": {"application/json"}}, true},
		{"lowercase known", http.Header{"x-api-key": {"k"}, "authorization": {"Bearer k"}}, true},
		{"none", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newModelServer(t, `{}`)
			dir := runDir(t)
			call := testCall(m.url("/v1"))
			call.Header = tt.header
			_, err := openLog(t, dir).Send(context.Background(), m.client(t), call)
			conns, _ := m.stats()
			if tt.sent {
				if err != nil || conns != 1 {
					t.Fatalf("Send = %v, %d connections; want sent", err, conns)
				}
				return
			}
			if !errors.Is(err, ErrHeader) || conns != 0 {
				t.Fatalf("Send = %v, %d connections; want ErrHeader and nothing sent", err, conns)
			}
			checkNothingWritten(t, dir)
		})
	}
}
