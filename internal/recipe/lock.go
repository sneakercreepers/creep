package recipe

import (
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// The lock (ADR 0028): creep.lock lists every installed recipe file with
// the commit it came from and the SHA-256 of its bytes. It lives with the
// installed files in the operator's ~/.creep/recipes, never in the scanned
// repository.
const (
	LockFile         = "creep.lock"
	LockVersion      = 1
	MaxLockBytes     = 256 << 10
	MaxLockEntries   = 256
	MaxSourceFiles   = 32 // recipe files one source may install
	maxFileNameBytes = 64
	checksumPrefix   = "sha256:"
)

// ErrLock means creep.lock breaks its format. ErrTampered means an
// installed recipe file no longer matches its checksum: the scan fails
// closed (exit 2) before any model call.
var (
	ErrLock     = errors.New("creep.lock refused")
	ErrTampered = errors.New("installed recipe does not match creep.lock")
)

// Lock is creep.lock: a closed JSON format, decoded as strictly as a
// recipe.
type Lock struct {
	Version int   `json:"version"`
	Recipes []Pin `json:"recipes"`
}

// Pin is one installed recipe file.
type Pin struct {
	Source   string `json:"source"` // github.com/<owner>/<repo>, lower case
	Commit   string `json:"commit"`
	File     string `json:"file"`     // the file's name in the source's recipes/ directory
	Checksum string `json:"checksum"` // sha256:<64 hex>
}

// NewLock is an empty lock of the current version.
func NewLock() Lock { return Lock{Version: LockVersion, Recipes: []Pin{}} }

// ParseLock reads creep.lock and checks every entry: a canonical source, a
// full commit, a recipe file name, a checksum, one commit per source and
// no file listed twice.
func ParseLock(data []byte) (Lock, error) {
	if len(data) > MaxLockBytes || !utf8.Valid(data) {
		return Lock{}, fmt.Errorf("%w: larger than %d bytes or not UTF-8", ErrLock, MaxLockBytes)
	}
	var l Lock
	if err := decodeStrict(data, &l, "lock"); err != nil {
		return Lock{}, fmt.Errorf("%w: %w", ErrLock, err)
	}
	if l.Version != LockVersion {
		return Lock{}, fmt.Errorf("%w: version must be %d", ErrLock, LockVersion)
	}
	if len(l.Recipes) > MaxLockEntries {
		return Lock{}, fmt.Errorf("%w: at most %d recipes", ErrLock, MaxLockEntries)
	}
	if l.Recipes == nil {
		l.Recipes = []Pin{}
	}
	return l, l.checkPins()
}

// checkPins checks each entry and the entries against each other.
func (l Lock) checkPins() error {
	commits := map[string]string{}
	files := map[string]bool{}
	for i, p := range l.Recipes {
		if _, err := p.Pinned(); err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrLock, i+1, err)
		}
		if !ValidFileName(p.File) || !validChecksum(p.Checksum) || reservedSegment(p.Path()) {
			return fmt.Errorf("%w: entry %d: want a .json file name and a sha256: checksum", ErrLock, i+1)
		}
		if c, seen := commits[p.Source]; seen && c != p.Commit {
			return fmt.Errorf("%w: entry %d: a source is pinned to two commits", ErrLock, i+1)
		}
		commits[p.Source] = p.Commit
		if files[p.Source+"/"+p.File] {
			return fmt.Errorf("%w: entry %d: a file is listed twice", ErrLock, i+1)
		}
		files[p.Source+"/"+p.File] = true
	}
	return nil
}

// Pinned is the entry's source and commit. The source must be written as
// ParseSource writes it, so one repository has one spelling in the lock.
func (p Pin) Pinned() (Source, error) {
	src, err := ParseSource(p.Source + "@" + p.Commit)
	if err != nil {
		return Source{}, err
	}
	if src.Repository() != p.Source {
		return Source{}, fmt.Errorf("%w: the source must be lower case", ErrSource)
	}
	return src, nil
}

// Path is where the installed file lives under ~/.creep/recipes, slash
// separated: <owner>/<repo>/<commit>/<file>. Every part is checked
// (ParseLock), so it has no "..", separator or drive letter in it.
func (p Pin) Path() string {
	return strings.TrimPrefix(p.Source, sourceHost) + "/" + p.Commit + "/" + p.File
}

// Verify compares data with the entry's checksum, in constant time.
func (p Pin) Verify(data []byte) error {
	if subtle.ConstantTimeCompare([]byte(Checksum(data)), []byte(p.Checksum)) != 1 {
		return fmt.Errorf("%w: %s from %s", ErrTampered, p.File, p.Source)
	}
	return nil
}

// Install returns the lock with src's entries replaced by files (name to
// bytes), sorted by source and file. Other sources are kept.
func (l Lock) Install(src Source, files map[string][]byte) Lock {
	out := Lock{Version: LockVersion, Recipes: []Pin{}}
	for _, p := range l.Recipes {
		if p.Source != src.Repository() {
			out.Recipes = append(out.Recipes, p)
		}
	}
	for name, data := range files {
		out.Recipes = append(out.Recipes, Pin{Source: src.Repository(), Commit: src.Commit, File: name, Checksum: Checksum(data)})
	}
	slices.SortFunc(out.Recipes, func(a, b Pin) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.File, b.File))
	})
	return out
}

// Marshal writes the lock as indented JSON with a final newline.
func (l Lock) Marshal() ([]byte, error) {
	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("creep.lock: %w", err)
	}
	return append(out, '\n'), nil
}

// Checksum is the lock's checksum of data: sha256:<hex>.
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return checksumPrefix + hex.EncodeToString(sum[:])
}

// reservedSegment reports a path segment Windows treats as a device (con,
// nul, com1...) or trims (a trailing "."), which would not name the file
// the lock means.
func reservedSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		base, _, _ := strings.Cut(seg, ".")
		if strings.HasSuffix(seg, ".") || slices.Contains(windowsDevices, base) {
			return true
		}
	}
	return false
}

var windowsDevices = []string{
	"con", "prn", "aux", "nul",
	"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

func validChecksum(c string) bool {
	rest, ok := strings.CutPrefix(c, checksumPrefix)
	if !ok || len(rest) != 2*sha256.Size {
		return false
	}
	for i := range len(rest) {
		if !isHex(rest[i]) {
			return false
		}
	}
	return true
}

// ValidFileName reports a recipe file name creep installs: 6 to 64 bytes
// of a-z, 0-9, "-" and "_", ending in .json, so it is one path segment on
// every system and never a hidden file.
func ValidFileName(name string) bool {
	base, ok := strings.CutSuffix(name, ".json")
	if !ok || base == "" || len(name) > maxFileNameBytes || !lowerOrDigit(base[0]) {
		return false
	}
	for i := range len(base) {
		if c := base[i]; !lowerOrDigit(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
