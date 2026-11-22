package recipe

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sneakercreepers/creep/internal/reader"
)

// validate checks every rule decoding cannot, field by field.
func (r *Recipe) validate(check PoCCheck) error {
	if r.Version != Version {
		return fmt.Errorf("%w: version must be %d", ErrInvalid, Version)
	}
	if !validID(r.ID) {
		return fmt.Errorf("%w: id must be 2 to %d bytes of a-z, 0-9 and -, starting with a letter or digit", ErrInvalid, MaxIDBytes)
	}
	if _, ok := classes[r.Class]; !ok {
		return fmt.Errorf("%w: class must be one of %s", ErrInvalid, strings.Join(Classes(), ", "))
	}
	return errors.Join(
		checkList("applies_to", r.AppliesTo, MaxAppliesTo, validExt),
		checkList("sources", r.Sources, MaxSignatures, validSignature),
		checkList("sinks", r.Sinks, MaxSignatures, validSignature),
		checkHint(r.Hint),
		r.checkFixtures(),
		r.checkPoC(check),
	)
}

// validID reports an id of 2 to MaxIDBytes bytes of a-z, 0-9 and "-" that
// does not start with "-".
func validID(id string) bool {
	if len(id) < 2 || len(id) > MaxIDBytes || id[0] == '-' {
		return false
	}
	for i := range len(id) {
		if c := id[i]; !lowerOrDigit(c) && c != '-' {
			return false
		}
	}
	return true
}

func lowerOrDigit(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }

// checkList checks a list of 1 to most distinct entries, each valid.
func checkList(field string, list []string, most int, valid func(string) bool) error {
	if len(list) == 0 || len(list) > most {
		return fmt.Errorf("%w: %s must hold 1 to %d entries", ErrInvalid, field, most)
	}
	for i, v := range list {
		if !valid(v) {
			return fmt.Errorf("%w: %s entry %d breaks the format", ErrInvalid, field, i+1)
		}
		if slices.Index(list, v) != i {
			return fmt.Errorf("%w: %s entry %d repeats an earlier one", ErrInvalid, field, i+1)
		}
	}
	return nil
}

// validExt reports a file extension: "." and 1 to 10 a-z or 0-9.
func validExt(e string) bool {
	if len(e) < 2 || len(e) > MaxExtBytes || e[0] != '.' {
		return false
	}
	for i := 1; i < len(e); i++ {
		if !lowerOrDigit(e[i]) {
			return false
		}
	}
	return true
}

// validSignature reports a lexical signature like the tripwire table's:
// MinSignature to MaxSignature bytes of printable ASCII, not starting or
// ending with a space.
func validSignature(s string) bool {
	if len(s) < MinSignature || len(s) > MaxSignature || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	return printableASCII(s, false)
}

// printableASCII reports bytes 0x20 to 0x7e only, and "\n" when newline.
func printableASCII(s string, newline bool) bool {
	for i := range len(s) {
		c := s[i]
		if (c < 0x20 || c > 0x7e) && (c != '\n' || !newline) {
			return false
		}
	}
	return true
}

// checkHint holds the hint to the reader's limits and to printable ASCII
// lines, so the HINT block shows exactly what a reviewer reads.
func checkHint(h string) error {
	switch {
	case strings.TrimSpace(h) == "":
		return fmt.Errorf("%w: hint must not be empty", ErrInvalid)
	case len(h) > reader.MaxHintBytes:
		return fmt.Errorf("%w: hint must be at most %d bytes", ErrInvalid, reader.MaxHintBytes)
	case strings.Count(h, "\n")+1 > reader.MaxHintLines:
		return fmt.Errorf("%w: hint must be at most %d lines", ErrInvalid, reader.MaxHintLines)
	case !printableASCII(h, true):
		return fmt.Errorf("%w: hint must be printable ASCII and newlines", ErrInvalid)
	}
	return nil
}

// checkFixtures checks both fixtures and that they differ: a safe twin
// identical to the vulnerable program proves nothing.
func (r *Recipe) checkFixtures() error {
	f := r.Fixtures
	if f.Vulnerable.Code == f.Safe.Code {
		return fmt.Errorf("%w: the safe fixture must differ from the vulnerable one", ErrInvalid)
	}
	return errors.Join(
		r.checkFixture("vulnerable", f.Vulnerable),
		r.checkFixture("safe", f.Safe),
	)
}

// checkFixture bounds a fixture and checks that its source and sink lines
// hold one of the recipe's source and sink signatures, so the fixture
// exercises the recipe it is in.
func (r *Recipe) checkFixture(name string, f Fixture) error {
	lines := strings.Split(strings.TrimSuffix(f.Code, "\n"), "\n")
	switch {
	case f.Code == "" || len(f.Code) > MaxFixtureBytes || len(lines) > MaxFixtureLines:
		return fmt.Errorf("%w: fixtures.%s.code must be 1 to %d bytes and %d lines", ErrInvalid, name, MaxFixtureBytes, MaxFixtureLines)
	case !utf8.ValidString(f.Code) || strings.ContainsRune(f.Code, 0):
		return fmt.Errorf("%w: fixtures.%s.code must be UTF-8 without NUL", ErrInvalid, name)
	case !inRange(f.SourceLine, len(lines)) || !inRange(f.SinkLine, len(lines)):
		return fmt.Errorf("%w: fixtures.%s source_line and sink_line must be lines of its code", ErrInvalid, name)
	case !holdsAny(lines[f.SourceLine-1], r.Sources):
		return fmt.Errorf("%w: fixtures.%s source_line holds none of the sources", ErrInvalid, name)
	case !holdsAny(lines[f.SinkLine-1], r.Sinks):
		return fmt.Errorf("%w: fixtures.%s sink_line holds none of the sinks", ErrInvalid, name)
	}
	return nil
}

func inRange(n, last int) bool { return n >= 1 && n <= last }

func holdsAny(line string, signatures []string) bool {
	return slices.ContainsFunc(signatures, func(s string) bool { return strings.Contains(line, s) })
}

// checkPoC bounds the PoC and has the caller check it against the closed
// verify templates. An absent or null PoC is no PoC.
func (r *Recipe) checkPoC(check PoCCheck) error {
	if len(r.PoC) == 0 || bytes.Equal(r.PoC, []byte("null")) {
		r.PoC = nil
		return nil
	}
	if len(r.PoC) > MaxPoCBytes {
		return fmt.Errorf("%w: poc must be at most %d bytes", ErrInvalid, MaxPoCBytes)
	}
	if check == nil {
		return fmt.Errorf("%w: poc cannot be checked here", ErrInvalid)
	}
	if err := check(r.Class, r.PoC); err != nil {
		return fmt.Errorf("%w: poc: %w", ErrInvalid, err)
	}
	return nil
}
