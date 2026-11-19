package discover

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	inv, err := loadInventory()
	if err != nil {
		t.Fatal(err)
	}
	py := Entry{Language: lang(t, "python")}
	tests := []struct {
		name    string
		content string
		want    Entry
	}{
		{"app/main.py", "", py},
		{`app\main.PY`, "", py},
		{"web/App.TSX", "", Entry{Language: lang(t, "typescript")}},
		{"cmd/server/main.go", "", Entry{Language: lang(t, "go")}},
		{"src/Main.java", "", Entry{Language: lang(t, "java")}},
		{"index.php", "", Entry{Language: lang(t, "php")}},
		{"app/models/user.rb", "", Entry{Language: lang(t, "ruby")}},
		{"Controllers/Home.cshtml", "", Entry{Language: lang(t, "csharp")}},
		{"package.json", "", Entry{Manifest: manifest(t, "npm")}},
		{"sub/go.mod", "", Entry{Manifest: manifest(t, "gomod")}},
		{"requirements-dev.txt", "", Entry{Manifest: manifest(t, "pip")}},
		{"api/Api.csproj", "", Entry{Manifest: manifest(t, "nuget")}},
		{"mix.exs", "", Entry{Manifest: manifest(t, "mix")}},
		{"Dockerfile", "", Entry{Container: container(t, "dockerfile")}},
		{"build/web.dockerfile", "", Entry{Container: container(t, "dockerfile")}},
		{"docker-compose.yml", "", Entry{Container: container(t, "compose")}},
		// Shebangs only for extensionless files, through env and its flags.
		{"bin/serve", "#!/usr/bin/env python3.12\nimport os\n", py},
		{"bin/serve", "#!/usr/bin/env -S node --no-warnings\n", Entry{Language: lang(t, "javascript")}},
		{"bin/serve", "#!/bin/sh\n", Entry{}},
		{"bin/serve.txt", "#!/usr/bin/python\n", Entry{}},
		{"bin/serve", "no shebang", Entry{}},
		// Not source: no rule, or binary.
		{"README.md", "", Entry{}},
		{"dockerfile", "", Entry{}}, // exact names match with case
		{"app/main.py", "abc\x00def", Entry{}},
		{"app/main.py", strings.Repeat("a", binaryProbeBytes) + "\x00", py},
		{"package.json", "\x00", Entry{Manifest: manifest(t, "npm")}},
	}
	for _, tt := range tests {
		if got := inv.classify(tt.name, []byte(tt.content)); got != tt.want {
			t.Errorf("classify(%q, %.20q) = %+v, want %+v", tt.name, tt.content, got, tt.want)
		}
	}
}

func lang(t *testing.T, name string) Language {
	t.Helper()
	return Language(id(t, languageNames, name))
}

func manifest(t *testing.T, name string) Manifest {
	t.Helper()
	return Manifest(id(t, manifestNames, name))
}

func container(t *testing.T, name string) Container {
	t.Helper()
	return Container(id(t, containerNames, name))
}

func id(t *testing.T, names []string, name string) uint8 {
	t.Helper()
	i := indexOf(names, name)
	if i < 0 {
		t.Fatalf("no ID %q", name)
	}
	return uint8(i + 1) //nolint:gosec // short list
}

func TestParseInventoryRejects(t *testing.T) {
	for _, row := range []string{
		"ext .py language",
		"ext .py language cobol",
		"suffix .py language python",
		"ext .py dialect python",
		"glob *.a*b manifest npm",
		"glob nostar manifest npm",
		"ext .py language python\next .py language go",
	} {
		if _, err := parseInventory(row); err == nil {
			t.Errorf("parseInventory(%q) accepted a broken row", row)
		}
	}
}

func TestCanaryLanguage(t *testing.T) {
	if canaryLanguage.String() != "javascript" {
		t.Fatalf("canary language = %s", canaryLanguage)
	}
}
