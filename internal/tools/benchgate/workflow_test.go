package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	digestLine = regexp.MustCompile(`(?m)^      BASE_MODEL_DIGEST: ([0-9a-f]{64})$`)
	modelLine  = regexp.MustCompile(`(?m)^      BENCH_MODEL: (\S+)$`)
)

// The gate matches a baseline by contract and model name, so the nightly
// model's name must carry its digest: a re-pin then reads as another model
// and fails until the baseline is set again, instead of being compared with
// numbers another model produced.
func TestBenchModelNameCarriesDigest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "bench.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := strings.ReplaceAll(string(data), "\r\n", "\n")
	digest := digestLine.FindStringSubmatch(wf)
	model := modelLine.FindStringSubmatch(wf)
	if digest == nil || model == nil {
		t.Fatal("bench.yml: no BASE_MODEL_DIGEST or literal BENCH_MODEL in the local job")
	}
	if want := "-" + digest[1][:12]; !strings.HasSuffix(model[1], want) {
		t.Fatalf("BENCH_MODEL %q must end with %q", model[1], want)
	}
}

// Protection (v0.3 release review L2): workflow logs and artifacts of this
// public repository are public. The cloud job uploads only the results
// (counts and the model name), never the recorded fixture (endpoint, raw
// replies) or the run directory (egress.log), and the policy script masks
// a cloud endpoint before it prints anything.
func TestCloudBenchPublishesNoEndpointOrReplies(t *testing.T) {
	wf := readRepo(t, ".github", "workflows", "bench.yml")
	start := strings.Index(wf, "\n  cloud:\n")
	if start < 0 {
		t.Fatal("bench.yml: no cloud job")
	}
	cloud := wf[start:]
	policy := readRepo(t, ".github", "scripts", "bench-policy.sh")
	tests := []struct {
		name, text, needle string
		want               bool
	}{
		{"uploads only the results", cloud, "path: ${{ runner.temp }}/bench-out/results.json\n", true},
		{"no fixture collected", cloud, "bench-fixture.json", false},
		{"no run directory uploaded", cloud, ".creep/runs", false},
		{"no debug artifact", cloud, "bench-cloud-debug", false},
		{"endpoint is no variable", cloud, "vars.BENCH_ENDPOINT", false},
		{"endpoint only in the policy step", cloud, "      - name: Policy, outside the repository\n        env:\n          BENCH_ENDPOINT: ${{ secrets.BENCH_ENDPOINT }}\n", true},
		{"endpoint masked", policy, `echo "::add-mask::$endpoint"`, true},
		{"host masked", policy, `echo "::add-mask::$host"`, true},
		{"origin never printed", policy, `at $origin"`, false},
	}
	for _, tt := range tests {
		if got := strings.Contains(tt.text, tt.needle); got != tt.want {
			t.Errorf("%s: contains %q = %t, want %t", tt.name, tt.needle, got, tt.want)
		}
	}
	if n := strings.Count(cloud, "BENCH_ENDPOINT:"); n != 1 {
		t.Errorf("the cloud job names BENCH_ENDPOINT %d times; only the policy step may get it", n)
	}
}

// #363: the nightly local job runs a real calibration of the pinned model
// and publishes its cost with the results; the cloud job does not, so a
// dispatch never pays for a calibration nobody asked for.
func TestNightlyBenchMeasuresCalibration(t *testing.T) {
	wf := readRepo(t, ".github", "workflows", "bench.yml")
	start := strings.Index(wf, "\n  cloud:\n")
	if start < 0 {
		t.Fatal("bench.yml: no cloud job")
	}
	local, cloud := wf[:start], wf[start:]
	if !strings.Contains(local, "./creep bench --record --recalibrate --format json >bench-out/results.json") {
		t.Error("the local job does not calibrate the pinned model")
	}
	if !strings.Contains(local, "- name: Calibration cost") {
		t.Error("the local job does not publish the calibration cost")
	}
	if strings.Contains(cloud, "--recalibrate") {
		t.Error("the cloud job calibrates")
	}
}

func readRepo(t *testing.T, elem ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", ".."}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// A re-pinned model fails against the old baseline.
func TestRepinFailsAgainstOldBaseline(t *testing.T) {
	base := withModel(results(baseTier), "creep-bench-qwen2.5-coder-1.5b-d7372fd82851")
	got := withModel(results(baseTier), "creep-bench-qwen2.5-coder-1.5b-0123456789ab")
	problems, err := compare(base, got, DefaultMaxDrop)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "set the baseline again") {
		t.Fatalf("problems %q, want one model mismatch", problems)
	}
}
