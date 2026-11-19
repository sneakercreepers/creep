package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// Protection (ADR 0017, #265): a repository in a language creep has no
// grammar for is evaluated, never listed unsupported_language: its known
// shell sink reaches the reader through the tripwire alone, even with a
// model that proposes nothing, and the complete run exits 1 over the gate,
// not 4. Before #265 each of these exited 4 with nothing evaluated.
func TestScanEvaluatesAnyLanguage(t *testing.T) {
	tests := []struct {
		name, file, src string
		line            int
	}{
		{"go", "cmd/run.go", "package main\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc run(w http.ResponseWriter, r *http.Request) {\n\tout, _ := exec.Command(\"sh\", \"-c\", r.URL.Query().Get(\"c\")).Output()\n\tw.Write(out)\n}\n", 9},
		{"php", "public/run.php", "<?php\n$c = $_GET['c'];\necho shell_exec($c);\n", 3},
		{"java", "src/Run.java", "class Run {\n  void run(javax.servlet.http.HttpServletRequest req) throws Exception {\n    Runtime.getRuntime().exec(req.getParameter(\"c\"));\n  }\n}\n", 3},
		{"ruby", "app/run.rb", "class RunController < ApplicationController\n  def run\n    Kernel.system(params[:c])\n  end\nend\n", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{tt.file: tt.src, "README.md": "# app\n"}, "")
			m := &fakeModel{verdict: map[string]string{"command_injection": "vulnerable"}}
			code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			want := fmt.Sprintf("probable  command_injection  %s:%d", tt.file, tt.line)
			if code != exitcode.GateExceeded || !strings.Contains(out, want) || strings.Contains(out, "unsupported_language") {
				t.Fatalf("exit %d, want %d and %q\n%s\n%s", code, exitcode.GateExceeded, want, out, errOut)
			}
			if !strings.Contains(out, "language "+tt.name+" 1") {
				t.Errorf("inventory does not name %s:\n%s", tt.name, out)
			}
			checkJSONReport(t, "")
			rep, err := readLastReport()
			if err != nil || len(rep.Coverage.NotEvaluated) != 0 || rep.Findings[0].Status != report.StatusProbable {
				t.Fatalf("report %+v, %v", rep, err)
			}
		})
	}
}
