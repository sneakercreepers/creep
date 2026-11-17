package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Report limits beyond the byte cap.
const (
	maxPathBytes = 4096
	maxLine      = 1 << 24
)

// gitleaksFinding is the part of a gitleaks JSON finding creep reads; the
// match, secret, commit and author fields are never decoded.
type gitleaksFinding struct {
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	RuleID    string `json:"RuleID"`
}

func parseGitleaks(data []byte, repo string, max int) ([]Finding, Failure) {
	var in []gitleaksFinding
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, FailMalformed
	}
	var c collector
	for _, f := range in {
		if f.StartLine < 0 || f.StartLine > maxLine {
			return nil, FailMalformed
		}
		if failure := c.add(repo, f.File, f.StartLine, max, "gitleaks", f.RuleID); failure != FailNone {
			return nil, failure
		}
	}
	return c.out, FailNone
}

// osvOutput is the part of osv-scanner's JSON report creep reads.
type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// parseOSV gives one finding per advisory per package per lockfile, at
// the lockfile (line 0).
func parseOSV(data []byte, repo string, max int) ([]Finding, Failure) {
	var in osvOutput
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, FailMalformed
	}
	var c collector
	for _, r := range in.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				failure := c.add(repo, r.Source.Path, 0, max, "osv-scanner", p.Package.Ecosystem, p.Package.Name, p.Package.Version, v.ID)
				if failure != FailNone {
					return nil, failure
				}
			}
		}
	}
	return c.out, FailNone
}

// collector checks and deduplicates findings by key.
type collector struct {
	out  []Finding
	seen map[string]bool
}

func (c *collector) add(repo, path string, line, max int, parts ...string) Failure {
	rel, ok := repoRelative(path, repo)
	if !ok {
		return FailPath
	}
	key := findingKey(rel, line, parts)
	if c.seen[key] {
		return FailNone
	}
	if len(c.out) >= max {
		return FailTooMany
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[key] = true
	c.out = append(c.out, Finding{Path: rel, Line: line, Key: key})
	return FailNone
}

// repoRelative turns a reported path into a slash-separated path inside
// repo. A relative path is taken as relative to repo; anything that leaves
// it, is empty, too long or not UTF-8 is refused, and so is a name the
// report refuses (report.ValidPath): one holding a backslash or starting
// like a drive letter, which Unix allows but Windows reads as a separator
// or a volume.
func repoRelative(path, repo string) (string, bool) {
	if path == "" || len(path) > maxPathBytes || !utf8.ValidString(path) {
		return "", false
	}
	rel := path
	if filepath.IsAbs(path) {
		var err error
		if rel, err = filepath.Rel(repo, path); err != nil {
			return "", false
		}
	}
	rel = filepath.Clean(rel)
	if !filepath.IsLocal(rel) || rel == "." {
		return "", false // a finding names a file in the repository
	}
	slash := filepath.ToSlash(rel)
	if strings.ContainsRune(slash, '\\') || (len(slash) > 1 && slash[1] == ':') {
		return "", false
	}
	return slash, true
}

// findingKey hashes the location and the tool's identifiers, length-
// prefixed so no two inputs share a key by concatenation.
func findingKey(rel string, line int, parts []string) string {
	h := sha256.New()
	for _, p := range append([]string{rel, strconv.Itoa(line)}, parts...) {
		h.Write([]byte(strconv.Itoa(len(p)) + ":" + p))
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}
