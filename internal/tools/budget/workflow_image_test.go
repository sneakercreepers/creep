package main

import (
	"strings"
	"testing"
)

// Job container and service images must be pinned by digest like docker://
// actions (#44); a value the line scan cannot see fails too.
func TestCheckWorkflowImages(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name string
		yaml string
		want string // substring of the single problem; "" means allowed
	}{
		{"service image tag", "    services:\n      db:\n        image: node:latest\n", "image node:latest is not pinned by @sha256 digest"},
		{"container image tag", "    container:\n      image: node:22\n", "image node:22 is not pinned"},
		{"container shorthand tag", "    container: node:latest\n", "image node:latest is not pinned"},
		{"untagged image", "        image: postgres\n", "image postgres is not pinned"},
		{"quoted image", "        image: 'redis:7'\n", "image redis:7 is not pinned"},
		{"quoted key", "        \"image\": redis:7\n", "image redis:7 is not pinned"},
		{"flow style container", "    container: {image: node:latest, options: --cpus 1}\n", "image node:latest is not pinned"},
		{"flow style service", "    services: {db: {image: postgres}}\n", "image postgres is not pinned"},
		{"expression hides the image", "        image: ${{ matrix.image }}\n", "is not pinned by @sha256 digest"},
		{"block scalar image", "        image: >-\n          node@sha256:x\n", "image value must sit on the key's line"},
		{"block scalar container", "    container: |\n      node\n", "image value must sit on the key's line"},
		{"image on the next line", "        image:\n", "image value must sit on the key's line"},
		{"digest with tag", "        image: node:22" + digest + "\n", ""},
		{"digest only", "        image: ghcr.io/o/x" + digest + "\n", ""},
		{"container shorthand digest", "    container: node" + digest + "\n", ""},
		{"container mapping opens", "    container:\n", ""},
		{"short digest", "        image: node@sha256:abc\n", "is not pinned by @sha256 digest"},
		{"commented image", "        # image: node:latest\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkWorkflow("w.yml", []byte(tt.yaml)), tt.want)
		})
	}
}

// The step that reads the repository reports an unpinned image, so the
// acceptance case fails `make budget` and not only the helper.
func TestWorkflowProblemsReportsImage(t *testing.T) {
	root := writeTree(t, map[string]string{
		".github/workflows/ci.yml": "jobs:\n  t:\n    services:\n      db:\n        image: node:latest\n",
	})
	got, err := workflowProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	assertOneProblem(t, got, ".github/workflows/ci.yml:5: image node:latest is not pinned")
}
