package gatewaytest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

const ollamaReply = `{"id":"chatcmpl-213","object":"chat.completion","created":1795833373,"model":"m","system_fingerprint":"fp_ollama",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"{\"verdict\": \"vulnerable\"}"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":386,"prompt_tokens_details":{"cached_tokens":346},"completion_tokens":33,"total_tokens":419}}`

func TestLiveFromEnv(t *testing.T) {
	for _, tt := range []struct {
		name, endpoint, model string
		ok                    bool
		wantErr               bool
	}{
		{"unset", "", "", false, false},
		{"loopback", "http://127.0.0.1:11434/v1", "m", true, false},
		{"model without endpoint", "", "m", false, true},
		{"endpoint without model", "http://127.0.0.1:11434/v1", "", false, true},
		{"cloud endpoint", "https://api.example.com/v1", "m", false, true},
		{"https loopback", "https://127.0.0.1:11434/v1", "m", false, true},
		{"localhost name", "http://localhost:11434/v1", "m", false, true},
		{"no port", "http://127.0.0.1/v1", "m", false, true},
		{"userinfo", "http://u:p@127.0.0.1:11434/v1", "m", false, true},
		{"query", "http://127.0.0.1:11434/v1?key=x", "m", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(LiveEndpointEnv, tt.endpoint)
			t.Setenv(LiveModelEnv, tt.model)
			s, ok, err := LiveFromEnv()
			if ok != tt.ok || (err != nil) != tt.wantErr {
				t.Fatalf("ok %v err %v, want ok %v err %v", ok, err, tt.ok, tt.wantErr)
			}
			if ok && (s.Endpoint != tt.endpoint || s.Model != tt.model) {
				t.Fatalf("settings %+v", s)
			}
		})
	}
}

// Live sends through the real gateway (consent, egress.log) to a loopback
// endpoint and returns the reply with the provider's metadata stripped.
func TestLiveSendsThroughGatewayAndNormalizes(t *testing.T) {
	e := New(t, func([]byte) []byte { return []byte(ollamaReply) })
	send := Live(t, LiveSettings{Endpoint: e.URL() + "/v1", Model: "m"})
	r, err := send(context.Background(), gateway.Call{
		Endpoint: e.URL() + "/v1/chat/completions", Model: "m", Purpose: "reader",
		Payload: []byte(`{"model":"m"}`), ReserveTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Bodies()) != 1 || string(e.Bodies()[0]) != `{"model":"m"}` {
		t.Fatalf("endpoint got %q", e.Bodies())
	}
	if err := CheckReplyHygiene(r.Body); err != nil {
		t.Fatalf("normalized reply: %v\n%s", err, r.Body)
	}
	var got chatReply
	if err := json.Unmarshal(r.Body, &got); err != nil || got.Choices[0].Message.Content != `{"verdict": "vulnerable"}` || got.Usage.CompletionTokens != 33 {
		t.Fatalf("content or usage changed: %s (%v)", r.Body, err)
	}
}

// Another origin than the one Live was opened for is refused by the
// gateway before anything is sent.
func TestLiveRefusesOtherOrigin(t *testing.T) {
	e := New(t, func([]byte) []byte { return []byte(ollamaReply) })
	other := New(t, func([]byte) []byte { return []byte(ollamaReply) })
	send := Live(t, LiveSettings{Endpoint: e.URL() + "/v1", Model: "m"})
	_, err := send(context.Background(), gateway.Call{
		Endpoint: other.URL() + "/v1/chat/completions", Model: "m", Purpose: "reader",
		Payload: []byte(`{}`), ReserveTokens: 100,
	})
	if err == nil || other.Conns() != 0 {
		t.Fatalf("err %v, %d connections to the other origin", err, other.Conns())
	}
}

func TestLiveRefusesErrorStatusAndBadBody(t *testing.T) {
	for _, body := range []string{`not json`, `{"choices":[]}`} {
		e := New(t, func([]byte) []byte { return []byte(body) })
		send := Live(t, LiveSettings{Endpoint: e.URL() + "/v1", Model: "m"})
		_, err := send(context.Background(), gateway.Call{
			Endpoint: e.URL() + "/v1/chat/completions", Model: "m", Purpose: "reader", Payload: []byte(`{}`), ReserveTokens: 100,
		})
		if err == nil {
			t.Errorf("%s: no error", body)
		}
	}
}

func TestCheckReplyHygiene(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		ok         bool
	}{
		{"normalized", `{"id":"chatcmpl-replay","choices":[]}`, true},
		{"synthesized id", `{"id":"chatcmpl-fake"}`, true},
		{"placeholder endpoint", `{"note":"https://models.replay.invalid/v1"}`, true},
		{"provider id", `{"id":"chatcmpl-213"}`, false},
		{"anthropic id", `{"id":"msg_01ABC"}`, false},
		{"fingerprint", `{"system_fingerprint":"fp_ollama"}`, false},
		{"created", `{"created":1}`, false},
		{"provider", `{"provider":"x"}`, false},
		{"loopback endpoint", `{"c":"http://127.0.0.1:11434/v1"}`, false},
		{"cloud endpoint", `{"c":"see https://api.example.com/v1"}`, false},
		{"key", fakeSecret("sk-", "abcdefghijklmnop"), false},
		{"bearer", fakeSecret("Bearer ", "abcdefghijkl"), false},
		{"stripe-style key", fakeSecret("sk_"+"live_", strings.Repeat("a", 24)), false},
		{"github token", fakeSecret("ghp"+"_", strings.Repeat("a", 36)), false},
		{"github fine-grained token", fakeSecret("github"+"_pat_", strings.Repeat("a", 22)+"_"+strings.Repeat("b", 59)), false},
		{"aws access key", fakeSecret("AKI"+"A", strings.Repeat("Q", 16)), false},
		{"bare loopback host and port", `{"c":"127.0.0.1:11434"}`, false},
		{"bare localhost and port", `{"c":"see localhost:8080"}`, false},
		{"bare cloud host and port", `{"c":"api.example.com:443"}`, false},
		{"placeholder host and port", `{"c":"models.replay.invalid:443"}`, true},
		{"source file and line", `{"c":"app.py:44 and server.js:120"}`, true},
		{"json numbers", `{"start":44,"end":120,"confidence":90}`, true},
		{"not json", `nope`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckReplyHygiene([]byte(tt.body)); (err == nil) != tt.ok {
				t.Fatalf("err %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestProvenanceRoundTripAndChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.json")
	live := Provenance{Model: "m", BaseModel: "b", BaseDigest: "d", Tier: "S", Recorded: "2026-11-28", Note: "n", Outcomes: map[string]string{"a": "b"}}
	if err := WriteProvenance(path, live); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadProvenance(path); err != nil || got.Model != "m" || got.Outcomes["a"] != "b" {
		t.Fatalf("read %+v, %v", got, err)
	}
	for _, tt := range []struct {
		name string
		edit func(*Provenance)
	}{
		{"no model", func(p *Provenance) { p.Model = "" }},
		{"no tier", func(p *Provenance) { p.Tier = "" }},
		{"bad date", func(p *Provenance) { p.Recorded = "yesterday" }},
		{"live without digest", func(p *Provenance) { p.BaseDigest = "" }},
		{"live without outcomes", func(p *Provenance) { p.Outcomes = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := live
			tt.edit(&p)
			if err := WriteProvenance(path, p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestReadProvenanceRefusesUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := WriteProvenance(path, SynthesizedProvenance("m", "M", "n")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProvenance(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(path, []byte(`{"synthesized":true,"model":"m","tier":"M","recorded":"2026-11-28","note":"n","extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProvenance(path); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("err %v", err)
	}
}

// fakeSecret is a reply holding prefix+rest, built at run time so no
// committed line looks like a real credential to a secret scanner.
func fakeSecret(prefix, rest string) string {
	return `{"c":"` + prefix + rest + `"}`
}
