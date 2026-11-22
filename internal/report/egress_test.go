package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func req(id, endpoint string) string {
	return fmt.Sprintf(`{"v":1,"type":"request","id":%q,"endpoint":%q,"model":"m","bytes":10,"redactions":{"K":1}}`, id, endpoint)
}

func TestSummarizeEgress(t *testing.T) {
	dh, err := SummarizeEgress(strings.NewReader(sampleEgress))
	if err != nil {
		t.Fatal(err)
	}
	if dh.Requests != 3 || dh.Bytes != 2050 || len(dh.Endpoints) != 2 {
		t.Fatalf("got %+v", dh)
	}
	api := dh.Endpoints[1]
	if api.Outcomes[OutcomeNoResult] != 1 || api.Outcomes["ok"] != 1 || api.InputTokens != 300 {
		t.Errorf("api endpoint %+v: a request without result must count as no_result", api)
	}
	if dh.Redactions["AWS_KEY"] != 3 || dh.Redactions["EMAIL"] != 1 {
		t.Errorf("redactions %v", dh.Redactions)
	}
}

func TestSummarizeEmptyEgress(t *testing.T) {
	dh, err := SummarizeEgress(strings.NewReader(""))
	if err != nil || dh.Requests != 0 || dh.Endpoints == nil || dh.Redactions == nil {
		t.Fatalf("got %+v, %v; want zero summary with empty collections", dh, err)
	}
}

func TestSummarizeEgressFailsClosed(t *testing.T) {
	many := func(n int, line func(i int) string) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(line(i) + "\n")
		}
		return b.String()
	}
	tests := map[string]string{
		"not JSON":               "garbage\n",
		"newer version":          `{"v":2,"type":"request","id":"a"}`,
		"unknown type":           `{"v":1,"type":"note","id":"a"}`,
		"result without request": `{"v":1,"type":"result","id":"a","outcome":"ok"}`,
		"result without outcome": req("a", "e") + "\n" + `{"v":1,"type":"result","id":"a"}`,
		"duplicate request":      req("a", "e") + "\n" + req("a", "e"),
		"request without ID":     req("", "e"),
		"negative bytes":         `{"v":1,"type":"request","id":"a","bytes":-1}`,
		"negative redactions":    `{"v":1,"type":"request","id":"a","redactions":{"K":-1}}`,
		"negative tokens":        req("a", "e") + "\n" + `{"v":1,"type":"result","id":"a","outcome":"ok","tokens":{"input":-5}}`,
		"line too long":          `{"v":1,"type":"request","id":"` + strings.Repeat("a", maxEgressLine) + `"}`,
		"too many endpoints": many(maxEgressEndpoints+1, func(i int) string {
			return req(fmt.Sprint("r", i), fmt.Sprint("https://e", i))
		}),
		"too many models": many(maxEndpointModels+1, func(i int) string {
			return fmt.Sprintf(`{"v":1,"type":"request","id":"r%d","endpoint":"e","model":"m%d"}`, i, i)
		}),
	}
	for name, log := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := SummarizeEgress(strings.NewReader(log)); !errors.Is(err, ErrEgressLog) {
				t.Errorf("error = %v, want ErrEgressLog", err)
			}
		})
	}
}

func TestSummarizeEgressIgnoresAdditiveFields(t *testing.T) {
	log := `{"v":1,"type":"request","id":"a","endpoint":"e","model":"m","bytes":5,"future_field":{"x":1}}`
	if dh, err := SummarizeEgress(strings.NewReader(log)); err != nil || dh.Bytes != 5 {
		t.Fatalf("got %+v, %v", dh, err)
	}
}

// TestSummarizeEgressReadsV1Fixture keeps the report reader on the committed
// v1 egress.log fixture the gateway's writer is pinned to (#135); the broken
// cases prove a retyped field fails the read.
func TestSummarizeEgressReadsV1Fixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "gateway", "testdata", "contract", "v1", "egress.log"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := string(data)
	tests := []struct {
		name string
		log  string
		ok   bool
	}{
		{"v1 fixture", fixture, true},
		{"broken: bytes retyped", strings.Replace(fixture, `"bytes":32`, `"bytes":"32"`, 1), false},
		{"broken: tokens retyped", strings.Replace(fixture, `"input":12`, `"input":"12"`, 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh, err := SummarizeEgress(strings.NewReader(tt.log))
			if !tt.ok {
				if err == nil {
					t.Fatalf("a retyped field was read: %+v", dh)
				}
				return
			}
			if err != nil || dh.Requests != 1 || dh.Bytes != 32 || dh.Redactions["SECRET_AWS"] != 1 || dh.Endpoints[0].InputTokens != 12 {
				t.Fatalf("got %+v, %v", dh, err)
			}
		})
	}
}
