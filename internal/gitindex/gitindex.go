package gitindex

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: git's index checksum, a format check, not a security control
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The git index (Documentation/gitformat-index.txt) lists every path git
// tracks. creep reads only what it needs to tell an installed dependency
// tree from committed code: the paths. It never runs git.
const (
	// MaxBytes is the largest index a caller should read; a repository of
	// several hundred thousand files has an index well under it.
	MaxBytes = 64 << 20
	// MaxPathBytes and MaxPathTotal bound what a version 4 index,
	// whose paths are prefix-compressed, can expand to.
	MaxPathBytes = 4096
	MaxPathTotal = 128 << 20
	// statBytes is the stat block every entry starts with: ctime, mtime,
	// dev, ino, mode, uid, gid and size.
	statBytes    = 40
	flagExtended = 0x4000
	headerSize   = 12
)

// ErrInvalid wraps every reason Parse refuses an index.
var ErrInvalid = errors.New("git index")

// Parse returns the tracked paths of a version 2, 3 or 4 index with
// a SHA-1 or SHA-256 checksum. The checksum is verified first and decides
// the hash length, so a misread can never yield made-up paths. An index it
// cannot read whole, one that needs an extension it does not know (split
// and sparse indexes), and one written without a checksum (index.skipHash)
// are errors: the caller then treats every vendor tree as unproven.
func Parse(data []byte) ([]string, error) {
	hashLen, err := hashLength(data)
	if err != nil {
		return nil, err
	}
	body := data[:len(data)-hashLen]
	if string(body[:4]) != "DIRC" {
		return nil, fmt.Errorf("%w: no DIRC signature", ErrInvalid)
	}
	r := reader{data: body, off: headerSize, hashLen: hashLen, version: binary.BigEndian.Uint32(body[4:8])}
	if r.version < 2 || r.version > 4 {
		return nil, fmt.Errorf("%w: version %d", ErrInvalid, r.version)
	}
	count := int(binary.BigEndian.Uint32(body[8:12]))
	paths := make([]string, 0, min(count, len(body)/(statBytes+hashLen+3)))
	prev := ""
	for range count {
		if prev, err = r.entry(prev); err != nil {
			return nil, err
		}
		paths = append(paths, prev)
	}
	return paths, r.extensions()
}

// hashLength is 20 for a SHA-1 index and 32 for a SHA-256 one: the
// length whose trailing checksum matches the bytes before it.
func hashLength(data []byte) (int, error) {
	if n := len(data) - sha1.Size; n >= headerSize {
		if sum := sha1.Sum(data[:n]); bytes.Equal(sum[:], data[n:]) { //nolint:gosec // G401: see the import
			return sha1.Size, nil
		}
	}
	if n := len(data) - sha256.Size; n >= headerSize {
		if sum := sha256.Sum256(data[:n]); bytes.Equal(sum[:], data[n:]) {
			return sha256.Size, nil
		}
	}
	return 0, fmt.Errorf("%w: checksum does not match", ErrInvalid)
}

type reader struct {
	data    []byte
	off     int
	hashLen int
	version uint32
	total   int // path bytes returned so far
}

// entry reads one index entry and returns its path. prev is the path of
// the entry before, which a version 4 path is relative to.
func (r *reader) entry(prev string) (string, error) {
	start := r.off
	fixed := statBytes + r.hashLen + 2
	if len(r.data)-r.off < fixed {
		return "", fmt.Errorf("%w: entry cut short", ErrInvalid)
	}
	flags := binary.BigEndian.Uint16(r.data[r.off+fixed-2:])
	r.off += fixed
	if flags&flagExtended != 0 {
		if r.version < 3 || len(r.data)-r.off < 2 {
			return "", fmt.Errorf("%w: bad extended flags", ErrInvalid)
		}
		r.off += 2
	}
	if r.version == 4 {
		return r.compressedPath(prev)
	}
	name, err := r.cString()
	if err != nil {
		return "", err
	}
	// Entries are NUL-padded to a multiple of eight bytes; the NUL that
	// ends the path is part of the padding.
	end := start + ((r.off - start - 1 + 8) &^ 7)
	if end > len(r.data) || bytes.Count(r.data[r.off:end], []byte{0}) != end-r.off {
		return "", fmt.Errorf("%w: bad entry padding", ErrInvalid)
	}
	r.off = end
	return r.keep(name)
}

// compressedPath reads a version 4 path: how many bytes to drop from the
// end of prev, then the rest of the path.
func (r *reader) compressedPath(prev string) (string, error) {
	strip, err := r.varint(len(prev))
	if err != nil {
		return "", err
	}
	suffix, err := r.cString()
	if err != nil {
		return "", err
	}
	return r.keep(prev[:len(prev)-strip] + suffix)
}

// varint decodes git's offset varint, refusing a value above limit.
func (r *reader) varint(limit int) (int, error) {
	val := 0
	for {
		if r.off >= len(r.data) {
			return 0, fmt.Errorf("%w: varint cut short", ErrInvalid)
		}
		c := r.data[r.off]
		r.off++
		val += int(c & 0x7f)
		if val > limit {
			return 0, fmt.Errorf("%w: path prefix out of range", ErrInvalid)
		}
		if c&0x80 == 0 {
			return val, nil
		}
		val = (val + 1) << 7
	}
}

// cString reads a NUL-terminated string and steps past the NUL.
func (r *reader) cString() (string, error) {
	n := bytes.IndexByte(r.data[r.off:], 0)
	if n < 0 {
		return "", fmt.Errorf("%w: path not terminated", ErrInvalid)
	}
	s := string(r.data[r.off : r.off+n])
	r.off += n + 1
	return s, nil
}

// keep bounds a path and the total path bytes, so a crafted version 4
// index cannot expand past them.
func (r *reader) keep(name string) (string, error) {
	r.total += len(name)
	if name == "" || len(name) > MaxPathBytes || r.total > MaxPathTotal {
		return "", fmt.Errorf("%w: path length out of range", ErrInvalid)
	}
	return name, nil
}

// extensions walks the extensions after the entries. An extension whose
// signature does not start with an uppercase letter is one git requires a
// reader to understand: the split index (link) keeps entries in another
// file and the sparse index (sdir) folds whole directories, so either one
// would hide tracked paths.
func (r *reader) extensions() error {
	for r.off < len(r.data) {
		if len(r.data)-r.off < 8 {
			return fmt.Errorf("%w: extension cut short", ErrInvalid)
		}
		sig := r.data[r.off : r.off+4]
		if sig[0] < 'A' || sig[0] > 'Z' {
			return fmt.Errorf("%w: required extension %q", ErrInvalid, sig)
		}
		size := int64(binary.BigEndian.Uint32(r.data[r.off+4:]))
		if size > int64(len(r.data)-r.off-8) {
			return fmt.Errorf("%w: extension %q cut short", ErrInvalid, sig)
		}
		r.off += 8 + int(size)
	}
	return nil
}
