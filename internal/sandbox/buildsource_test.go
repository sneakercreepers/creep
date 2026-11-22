package sandbox

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const plainDockerfile = "FROM alpine:3\nCOPY . /app\nCMD [\"/app/run\"]\n"

// memRepo is a repository held in memory; Read records every path read.
type memRepo struct {
	files map[string]string
	read  []string
}

func (m *memRepo) repo() Repo {
	paths := make([]string, 0, len(m.files))
	for p := range m.files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return Repo{Paths: paths, Read: func(p string) ([]byte, error) {
		m.read = append(m.read, p)
		data, ok := m.files[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(data), nil
	}}
}

func TestPlanBuild(t *testing.T) {
	tests := map[string]struct {
		files map[string]string
		want  buildPlan
	}{
		"root Dockerfile":  {map[string]string{"Dockerfile": plainDockerfile, "app.py": ""}, buildPlan{context: ".", dockerfile: "Dockerfile"}},
		"Containerfile":    {map[string]string{"Containerfile": plainDockerfile}, buildPlan{context: ".", dockerfile: "Containerfile"}},
		"compose string":   {map[string]string{"compose.yaml": "services:\n  web:\n    build: ./web\n", "web/Dockerfile": plainDockerfile}, buildPlan{context: "web", dockerfile: "web/Dockerfile"}},
		"compose mapping":  {map[string]string{"docker-compose.yml": "services:\n  web:\n    build:\n      context: srv\n      dockerfile: docker/App.dockerfile\n      target: Final\n", "srv/docker/App.dockerfile": "FROM alpine:3 AS final\n"}, buildPlan{context: "srv", dockerfile: "srv/docker/App.dockerfile", target: "Final"}},
		"compose first":    {map[string]string{"compose.yml": "services:\n  a:\n    build: .\n", "Dockerfile": plainDockerfile}, buildPlan{context: ".", dockerfile: "Dockerfile"}},
		"compose no build": {map[string]string{"compose.yaml": "services:\n  db:\n    image: postgres\n", "Dockerfile": plainDockerfile}, buildPlan{context: ".", dockerfile: "Dockerfile"}},
		// How services run is never passed on, so these are neutralized,
		// not refused: the app runs with creep's profile only.
		"runtime keys ignored": {map[string]string{"compose.yaml": "services:\n  web:\n    build: .\n    privileged: true\n    network_mode: host\n    pid: host\n    cap_add: [SYS_ADMIN]\n    devices: [/dev/kvm]\n    volumes: [/var/run/docker.sock:/var/run/docker.sock, /:/host]\n    extra_hosts: [evil:10.0.0.1]\n    ports: [\"80:80\"]\n    env_file: .env\n    networks: [outside]\nnetworks:\n  outside:\n    external: true\n", "Dockerfile": plainDockerfile}, buildPlan{context: ".", dockerfile: "Dockerfile"}},
		"anchors":              {map[string]string{"compose.yaml": "x-b: &b\n  context: web\nservices:\n  web:\n    build: *b\n", "web/Dockerfile": plainDockerfile}, buildPlan{context: "web", dockerfile: "web/Dockerfile"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			plan, why := planBuild((&memRepo{files: tt.files}).repo())
			if why != nil {
				t.Fatalf("refused: %s %s", why.reason, why.detail)
			}
			if plan.context != tt.want.context || plan.dockerfile != tt.want.dockerfile || plan.target != tt.want.target {
				t.Errorf("plan %+v, want %+v", plan, tt.want)
			}
		})
	}
}

// TestPlanBuildRefuses: a compose file is hostile input. Anything that
// changes how the image is built beyond a context, a Dockerfile and a
// target, or that points outside the repository, refuses the build with a
// closed reason and detail, never repository text.
func TestPlanBuildRefuses(t *testing.T) {
	df := map[string]string{"Dockerfile": plainDockerfile}
	compose := func(build string) map[string]string {
		return map[string]string{"compose.yaml": "services:\n  web:\n    build:\n" + build, "Dockerfile": plainDockerfile}
	}
	tests := map[string]struct {
		files  map[string]string
		reason BuildReason
		detail string
	}{
		"nothing":              {map[string]string{"app.py": ""}, BuildNoFile, ""},
		"nested Dockerfile":    {map[string]string{"web/Dockerfile": plainDockerfile}, BuildNoFile, ""},
		"compose only images":  {map[string]string{"compose.yaml": "services:\n  db:\n    image: postgres\n"}, BuildNoFile, "compose_without_build"},
		"include":              {withFile(df, "compose.yaml", "include:\n  - other.yaml\nservices: {}\n"), BuildComposeRefused, "include"},
		"extends":              {withFile(df, "compose.yaml", "services:\n  web:\n    extends: {file: x.yaml, service: y}\n    build: .\n"), BuildComposeRefused, "extends"},
		"merge key":            {withFile(df, "compose.yaml", "x: &x {privileged: true}\nservices:\n  web:\n    <<: *x\n    build: .\n"), BuildComposeRefused, "merge_key"},
		"merge key services":   {withFile(df, "compose.yaml", "x: &x {web: {build: {context: ..}}}\nservices:\n  <<: *x\n"), BuildComposeRefused, "merge_key"},
		"merge key root":       {withFile(df, "compose.yaml", "x: &x {include: [a.yaml]}\n<<: *x\nservices: {}\n"), BuildComposeRefused, "merge_key"},
		"alias key args":       {withFile(df, "compose.yaml", "k: &k args\nservices:\n  web:\n    build:\n      *k : {HTTP_PROXY: http://evil:3128}\n"), BuildComposeRefused, "build.args"},
		"alias key context":    {withFile(df, "compose.yaml", "k: &k context\nservices:\n  web:\n    build:\n      *k : ..\n"), BuildComposeRefused, "build.context"},
		"alias key extends":    {withFile(df, "compose.yaml", "k: &k extends\nservices:\n  web:\n    *k : {file: x.yaml, service: y}\n    build: .\n"), BuildComposeRefused, "extends"},
		"alias key include":    {withFile(df, "compose.yaml", "k: &k include\n*k : [other.yaml]\nservices: {}\n"), BuildComposeRefused, "include"},
		"several builds":       {withFile(df, "compose.yaml", "services:\n  a:\n    build: .\n  b:\n    build: .\n"), BuildComposeRefused, "several_builds"},
		"args":                 {compose("      args: {HTTP_PROXY: http://evil:3128}\n"), BuildComposeRefused, "build.args"},
		"secrets":              {compose("      secrets: [npmrc]\n"), BuildComposeRefused, "build.secrets"},
		"ssh":                  {compose("      ssh: [default]\n"), BuildComposeRefused, "build.ssh"},
		"network":              {compose("      network: host\n"), BuildComposeRefused, "build.network"},
		"extra hosts":          {compose("      extra_hosts: [registry:10.0.0.1]\n"), BuildComposeRefused, "build.extra_hosts"},
		"additional contexts":  {compose("      additional_contexts: {home: /home/me}\n"), BuildComposeRefused, "build.additional_contexts"},
		"privileged":           {compose("      privileged: true\n"), BuildComposeRefused, "build.privileged"},
		"entitlements":         {compose("      entitlements: [network.host]\n"), BuildComposeRefused, "build.entitlements"},
		"inline Dockerfile":    {compose("      dockerfile_inline: FROM alpine\n"), BuildComposeRefused, "build.dockerfile_inline"},
		"cache from":           {compose("      cache_from: [evil.example/cache]\n"), BuildComposeRefused, "build.cache_from"},
		"unknown key":          {compose("      \"x\\e[31m\": 1\n"), BuildComposeRefused, "build.unknown_key"},
		"context parent":       {compose("      context: ..\n"), BuildComposeRefused, "build.context"},
		"context parent deep":  {compose("      context: a/../../b\n"), BuildComposeRefused, "build.context"},
		"context absolute":     {compose("      context: /etc\n"), BuildComposeRefused, "build.context"},
		"context url":          {compose("      context: https://github.com/o/r.git\n"), BuildComposeRefused, "build.context"},
		"context git":          {compose("      context: git@github.com:o/r.git\n"), BuildComposeRefused, "build.context"},
		"context variable":     {compose("      context: ${HOME}\n"), BuildComposeRefused, "build.context"},
		"context backslash":    {compose("      context: ..\\\\x\n"), BuildComposeRefused, "build.context"},
		"context not a string": {compose("      context: 12\n"), BuildComposeRefused, "build.context"},
		"dockerfile outside":   {compose("      dockerfile: ../Dockerfile\n"), BuildComposeRefused, "build.dockerfile"},
		"dockerfile absolute":  {compose("      dockerfile: /etc/passwd\n"), BuildComposeRefused, "build.dockerfile"},
		"dockerfile cpp":       {withFile(compose("      dockerfile: Containerfile.in\n"), "Containerfile.in", "#define SRC http://evil.example/x\nFROM busybox\nADD SRC /x\n"), BuildDockerfileRefused, "preprocessed"},
		"dockerfile cpp upper": {withFile(compose("      dockerfile: d/Dockerfile.IN\n"), "d/Dockerfile.IN", plainDockerfile), BuildDockerfileRefused, "preprocessed"},
		"dockerfile variable":  {compose("      dockerfile: ${DF}\n"), BuildComposeRefused, "build.dockerfile"},
		"target variable":      {compose("      target: ${T}\n"), BuildComposeRefused, "build.target"},
		"dockerfile missing":   {compose("      dockerfile: Other\n"), BuildComposeRefused, "dockerfile_not_in_repository"},
		"target flag":          {compose("      target: --allow=network.host\n"), BuildComposeRefused, "build.target"},
		"target unknown stage": {compose("      target: nope\n"), BuildComposeRefused, "build.target"},
		"build null":           {withFile(df, "compose.yaml", "services:\n  web:\n    build:\n"), BuildComposeRefused, "build.context"},
		"build list":           {withFile(df, "compose.yaml", "services:\n  web:\n    build: [a]\n"), BuildComposeRefused, "build"},
		"services list":        {withFile(df, "compose.yaml", "services: [a]\n"), BuildComposeRefused, "services"},
		"not yaml":             {withFile(df, "compose.yaml", "services: [\n"), BuildComposeRefused, "parse"},
		"not a mapping":        {withFile(df, "compose.yaml", "- a\n"), BuildComposeRefused, "parse"},
		"compose too large":    {withFile(df, "compose.yaml", strings.Repeat("#", maxBuildFileBytes+1)), BuildComposeRefused, "too_large"},
		"dockerfile refused":   {map[string]string{"Dockerfile": "FROM alpine:3\nADD https://example.com/x /x\n"}, BuildDockerfileRefused, ruleRemoteAdd},
		"dockerfile too large": {map[string]string{"Dockerfile": strings.Repeat("#", maxBuildFileBytes+1)}, BuildDockerfileRefused, "too_large"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, why := planBuild((&memRepo{files: tt.files}).repo())
			if why == nil {
				t.Fatal("planned")
			}
			if why.reason != tt.reason || why.detail != tt.detail {
				t.Errorf("refused %s %q, want %s %q", why.reason, why.detail, tt.reason, tt.detail)
			}
		})
	}
}

func withFile(base map[string]string, name, data string) map[string]string {
	out := map[string]string{name: data}
	for k, v := range base {
		out[k] = v
	}
	return out
}

// TestPlanReadsOnlyBuildFiles: planning reads the compose file and the
// Dockerfile through the caller's reader, nothing else, and an unclean
// path in the file list is never a build file.
func TestPlanReadsOnlyBuildFiles(t *testing.T) {
	m := &memRepo{files: map[string]string{"compose.yaml": "services:\n  w:\n    build: .\n", "Dockerfile": plainDockerfile, ".env": "SECRET=1", "app.py": ""}}
	if _, why := planBuild(m.repo()); why != nil {
		t.Fatalf("refused: %+v", why)
	}
	if !slices.Equal(m.read, []string{"compose.yaml", "Dockerfile"}) {
		t.Errorf("read %q", m.read)
	}
	for _, p := range []string{"./Dockerfile", "/Dockerfile", "a/../Dockerfile"} {
		repo := Repo{Paths: []string{p}, Read: func(string) ([]byte, error) { return []byte(plainDockerfile), nil }}
		if _, why := planBuild(repo); why == nil || why.reason != BuildNoFile {
			t.Errorf("path %q: %+v", p, why)
		}
	}
}
