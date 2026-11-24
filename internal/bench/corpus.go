package bench

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

//go:embed corpus
var corpusFS embed.FS

// Variant is one twin of a case.
type Variant string

const (
	Vulnerable Variant = "vulnerable"
	Safe       Variant = "safe"
)

// Variants are the twins in the order the bench runs them.
func Variants() []Variant { return []Variant{Vulnerable, Safe} }

// maxSourceBytes bounds one twin: the corpus is small hand-written code.
const maxSourceBytes = 64 << 10

// Classes are the vulnerability classes a case may name: calibration's and
// template injection, the names creep's reports use.
var classes = []string{
	"sqli", "nosql_injection", "command_injection", "path_traversal", "ssrf",
	"idor", "missing_auth", "prototype_pollution", "template_injection",
}

var languages = []string{"go", "java", "javascript", "php", "python", "ruby"}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	filePattern = regexp.MustCompile(`^[A-Za-z0-9_]+\.[a-z]+$`)
)

// Case is one bench case: a planted vulnerability and its safe twin.
type Case struct {
	ID       string
	Class    string
	Language string
	File     string // the name the scan sees for either twin
	twins    map[Variant]Twin
}

// Twin is one variant's code and the lines that matter to scoring.
type Twin struct {
	Source []byte
	Entry  int // 1-based line of the entry point
	Sink   int // 1-based line of the sink
}

// Twin returns the case's v variant.
func (c Case) Twin(v Variant) Twin { return c.twins[v] }

// caseFile is case.json, version 1, decoded strictly.
type caseFile struct {
	Version    int     `json:"version"`
	ID         string  `json:"id"`
	Class      string  `json:"class"`
	Language   string  `json:"language"`
	File       string  `json:"file"`
	Vulnerable markers `json:"vulnerable"`
	Safe       markers `json:"safe"`
}

type markers struct {
	Entry string `json:"entry"`
	Sink  string `json:"sink"`
}

// Corpus loads every embedded case, sorted by ID.
func Corpus() ([]Case, error) {
	return loadCorpus(corpusFS, "corpus")
}

func loadCorpus(fsys fs.FS, dir string) ([]Case, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("bench corpus: %w", err)
	}
	var out []Case
	for _, e := range entries {
		c, err := loadCase(fsys, path.Join(dir, e.Name()), e.Name())
		if err != nil {
			return nil, fmt.Errorf("bench case %s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("bench corpus is empty")
	}
	return out, nil
}

func loadCase(fsys fs.FS, dir, name string) (Case, error) {
	raw, err := fs.ReadFile(fsys, path.Join(dir, "case.json"))
	if err != nil {
		return Case{}, err
	}
	var cf caseFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		return Case{}, fmt.Errorf("case.json: %w", err)
	}
	if err := cf.check(name); err != nil {
		return Case{}, err
	}
	c := Case{ID: cf.ID, Class: cf.Class, Language: cf.Language, File: cf.File, twins: map[Variant]Twin{}}
	for v, m := range map[Variant]markers{Vulnerable: cf.Vulnerable, Safe: cf.Safe} {
		if c.twins[v], err = loadTwin(fsys, path.Join(dir, string(v)+".src"), m); err != nil {
			return Case{}, fmt.Errorf("%s: %w", v, err)
		}
	}
	return c, nil
}

func (cf caseFile) check(dir string) error {
	switch {
	case cf.Version != 1:
		return errors.New("case.json: version must be 1")
	case cf.ID != dir || !idPattern.MatchString(cf.ID):
		return errors.New("case.json: id must be the directory name, lowercase words joined by '-'")
	case !slices.Contains(classes, cf.Class):
		return errors.New("case.json: class is not one creep reports")
	case !slices.Contains(languages, cf.Language):
		return errors.New("case.json: language is not one the corpus lists")
	case !filePattern.MatchString(cf.File):
		return errors.New("case.json: file must be a plain file name with an extension")
	}
	return nil
}

func loadTwin(fsys fs.FS, name string, m markers) (Twin, error) {
	src, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Twin{}, err
	}
	if len(src) > maxSourceBytes {
		return Twin{}, errors.New("source over 64 KiB")
	}
	entry, err := markerLine(src, m.Entry)
	if err != nil {
		return Twin{}, fmt.Errorf("entry: %w", err)
	}
	sink, err := markerLine(src, m.Sink)
	if err != nil {
		return Twin{}, fmt.Errorf("sink: %w", err)
	}
	if entry > sink {
		return Twin{}, errors.New("entry line is after the sink line")
	}
	return Twin{Source: src, Entry: entry, Sink: sink}, nil
}

// markerLine is the 1-based line holding marker, which must be on exactly
// one line.
func markerLine(src []byte, marker string) (int, error) {
	if marker == "" {
		return 0, errors.New("marker is empty")
	}
	found := 0
	for i, line := range strings.Split(string(src), "\n") {
		if !strings.Contains(line, marker) {
			continue
		}
		if found != 0 {
			return 0, errors.New("marker is on more than one line")
		}
		found = i + 1
	}
	if found == 0 {
		return 0, errors.New("marker is on no line")
	}
	return found, nil
}

// Digest is the SHA-256 of every corpus file, by path, so published
// numbers name the corpus they measured.
func Digest() (string, error) {
	h := sha256.New()
	err := fs.WalkDir(corpusFS, "corpus", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := corpusFS.ReadFile(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", p, len(data))
		h.Write(data)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("bench corpus digest: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
