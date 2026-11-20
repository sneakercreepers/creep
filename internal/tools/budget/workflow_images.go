package main

import (
	"regexp"
	"strings"
)

var (
	// imageKey and containerKey find a job container or service image written
	// on its key's line, as `image:` or as the `container: <image>` shorthand,
	// in block or flow style.
	imageKey     = regexp.MustCompile(`(?:^|[\s{,\-])["']?image["']?\s*:\s*["']?([^\s"',}#]*)`)
	containerKey = regexp.MustCompile(`(?:^|[\s{,\-])["']?container["']?\s*:\s*["']?([^\s"',}#]*)`)
	// bareContainer and servicesKey match a line holding only that key.
	bareContainer = regexp.MustCompile(`^["']?container["']?\s*:$`)
	servicesKey   = regexp.MustCompile(`^["']?services["']?\s*:\s*(.*)$`)
	// plainKey matches a `key: value` line, the shape of a mapping entry.
	plainKey = regexp.MustCompile(`^["']?[^\s"':{}\[\],]+["']?\s*:(?:\s+(.*))?$`)
)

const valueOnNextLine = "image value must sit on the key's line"

// imageProblems reports images on this line not pinned by digest. An
// `image:` with no value on its line (a block scalar, say) cannot be checked,
// so it fails too; a bare `container:` is imageScan's.
func imageProblems(code string) []string {
	var problems []string
	for _, m := range imageKey.FindAllStringSubmatch(code, -1) {
		problems = append(problems, unpinnedImage(m[1])...)
	}
	for _, m := range containerKey.FindAllStringSubmatch(code, -1) {
		if m[1] != "" && !strings.HasPrefix(m[1], "{") {
			problems = append(problems, unpinnedImage(m[1])...)
		}
	}
	return problems
}

func unpinnedImage(ref string) []string {
	ref = strings.Trim(ref, `"'`)
	switch {
	case ref == "", strings.HasPrefix(ref, "|"), strings.HasPrefix(ref, ">"):
		return []string{valueOnNextLine}
	case digestPin.MatchString(ref):
		return nil
	}
	return []string{"image " + ref + " is not pinned by @sha256 digest"}
}

// imageScan follows the images a single line cannot show: `container:` and
// service entries whose value starts on a later line, and the entries of a
// `services:` block, where `name: <image>` is a service image too.
type imageScan struct {
	pendingAt  string // location of a bare container or service key, "" for none
	pendingCol int
	services   int // key column of the open services block, -1 for none
	entryCol   int // column of its entries, -1 until the first
}

func newImageScan() *imageScan {
	return &imageScan{services: -1, entryCol: -1}
}

// line takes one YAML line (not block text or a quoted continuation) with
// its comment stripped.
func (s *imageScan) line(at, code string) []string {
	col := keyColumn(code)
	text := strings.TrimSpace(code[col:])
	if text == "" {
		return nil
	}
	problems := s.resolvePending(code, col, text)
	problems = append(problems, s.serviceEntry(at, col, text)...)
	return append(problems, s.openKeys(at, col, text)...)
}

// resolvePending accepts a bare key only when a deeper mapping follows: a
// block `key:` line or a flow mapping. A plain scalar, a sequence or nothing
// is an image the line scan cannot check.
func (s *imageScan) resolvePending(code string, col int, text string) []string {
	if s.pendingAt == "" {
		return nil
	}
	at := s.pendingAt
	s.pendingAt = ""
	nested := col > s.pendingCol && !strings.HasPrefix(strings.TrimLeft(code, " "), "-")
	if nested && (plainKey.MatchString(text) || strings.HasPrefix(text, "{")) {
		return nil
	}
	return []string{at + valueOnNextLine}
}

// serviceEntry checks a `name: value` line directly under `services:`.
func (s *imageScan) serviceEntry(at string, col int, text string) []string {
	if s.services < 0 {
		return nil
	}
	if col <= s.services {
		s.services = -1
		return nil
	}
	if s.entryCol < 0 {
		s.entryCol = col
	}
	if col != s.entryCol {
		return nil
	}
	m := plainKey.FindStringSubmatch(text)
	switch {
	case m == nil:
		return []string{at + "service entry is not a plain key; write services as a block mapping"}
	case m[1] == "":
		s.pendingAt, s.pendingCol = at, col
		return nil
	case strings.HasPrefix(m[1], "{"):
		return nil // a flow mapping; imageKey checks its image
	}
	return prefixed(at, unpinnedImage(strings.Fields(m[1])[0]))
}

func (s *imageScan) openKeys(at string, col int, text string) []string {
	if bareContainer.MatchString(text) {
		s.pendingAt, s.pendingCol = at, col
		return nil
	}
	m := servicesKey.FindStringSubmatch(text)
	switch {
	case m == nil:
		return nil
	case m[1] == "":
		s.services, s.entryCol = col, -1
		return nil
	}
	return []string{at + "services must be a block mapping so each image can be checked"}
}

// end reports a bare key left open at the end of the file.
func (s *imageScan) end() []string {
	if s.pendingAt == "" {
		return nil
	}
	return []string{s.pendingAt + valueOnNextLine}
}
