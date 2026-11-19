package static

import (
	"strings"
	"testing"
)

// TestDynamicImportSinks (#255 tester I3): a sink reached through
// __import__ or importlib.import_module of a literal is the same sink as
// through import; one whose module name is not a literal makes the route
// partial, never clean.
func TestDynamicImportSinks(t *testing.T) {
	const head = "from flask import Flask, request\nimport importlib\nfrom importlib import import_module\napp = Flask(__name__)\n"
	const route = "\n@app.get(\"/x\")\ndef x():\n    BODY\n    return 'x'\n"
	tests := []struct {
		name, top, body string
		wantSink        bool
		wantPartial     bool
	}{
		{"import", "import os\n", "os.system(request.args['c'])", true, false},
		{"inline __import__", "", "__import__(\"os\").system(request.args['c'])", true, false},
		{"escaped __import__", "", "__import__(\"\\x6fs\").system(request.args['c'])", true, false},
		{"dotted __import__ is the top package", "", "__import__(\"os.path\").system(request.args['c'])", true, false},
		{"import_module", "", "importlib.import_module(\"os\").system(request.args['c'])", true, false},
		{"from importlib", "", "import_module(\"os\").popen(request.args['c'])", true, false},
		{"module-level alias", "o = __import__(\"os\")\n", "o.system(request.args['c'])", true, false},
		{"fullwidth __import__", "", "__ｉｍｐｏｒｔ__(\"os\").system(request.args['c'])", true, false},
		{"computed inline", "", "__import__(request.args['m']).system('ls')", false, true},
		{"computed alias", "m = importlib.import_module(NAME)\n", "m.system('ls')", false, true},
		{"computed in a helper", "def h():\n    __import__(NAME).system('ls')\n", "h()", false, true},
		{"bare call is no sink", "", "__import__(NAME)", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := head + tt.top + strings.Replace(route, "BODY", tt.body, 1)
			g, _ := extractFile(t, "app.py", []byte(src))
			if len(g.Routes) != 1 {
				t.Fatalf("%d routes, want 1", len(g.Routes))
			}
			if got := len(g.Sinks) > 0; got != tt.wantSink {
				t.Errorf("sinks %+v, want a sink %v", g.Sinks, tt.wantSink)
			}
			if g.Routes[0].Partial != tt.wantPartial {
				t.Errorf("route partial = %v, want %v", g.Routes[0].Partial, tt.wantPartial)
			}
		})
	}
}
