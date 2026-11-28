package gitindextest

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: git's index checksum
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// statBytes is the stat block every entry starts with; flagExtended marks
// an entry with a second flags word (version 3 and up).
const (
	statBytes    = 40
	flagExtended = 0x4000
)

// Spec describes an index for Build. A zero HashLen is SHA-1; NoSign
// leaves the checksum zero, as index.skipHash does.
type Spec struct {
	Version  uint32
	HashLen  int
	Paths    []string
	Extended bool   // set the extended flag on every entry
	Count    int    // entry count in the header; 0 means len(Paths)
	Ext      []byte // raw bytes after the entries
	NoSign   bool
	Stats    map[string]Stat // by path; a path not named is a regular file of size and mtime 0
}

// Stat is the stat data Build writes for one entry. A zero Mode is a
// regular file (0100644).
type Stat struct {
	Mode, Size, MtimeSec uint32
}

// Build writes an index the way git does (gitformat-index.txt).
func Build(s Spec) []byte {
	if s.HashLen == 0 {
		s.HashLen = sha1.Size
	}
	count := s.Count
	if count == 0 {
		count = len(s.Paths)
	}
	var b bytes.Buffer
	b.WriteString("DIRC")
	b.Write(binary.BigEndian.AppendUint32(nil, s.Version))
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(count))) //nolint:gosec // G115: test sizes
	prev := ""
	for _, p := range s.Paths {
		writeEntry(&b, s, prev, p)
		prev = p
	}
	b.Write(s.Ext)
	return Sign(b.Bytes(), s.HashLen, s.NoSign)
}

func writeEntry(b *bytes.Buffer, s Spec, prev, p string) {
	start := b.Len()
	b.Write(statBlock(s.Stats[p]))
	b.Write(make([]byte, s.HashLen))
	flags := uint16(min(len(p), 0xfff)) //nolint:gosec // G115: bounded by min
	if s.Extended {
		flags |= flagExtended
	}
	b.Write(binary.BigEndian.AppendUint16(nil, flags))
	if s.Extended {
		b.Write([]byte{0, 0})
	}
	if s.Version == 4 {
		common := commonPrefixLen(prev, p)
		b.Write(Varint(len(prev) - common))
		b.WriteString(p[common:])
		b.WriteByte(0)
		return
	}
	b.WriteString(p)
	n := b.Len() - start
	b.Write(make([]byte, (n+8)&^7-n))
}

// statBlock is ctime, mtime, dev, ino, mode, uid, gid and size, as git
// lays them out; only mtime seconds, mode and size are set.
func statBlock(st Stat) []byte {
	if st.Mode == 0 {
		st.Mode = 0o100644
	}
	b := make([]byte, statBytes)
	binary.BigEndian.PutUint32(b[8:], st.MtimeSec)
	binary.BigEndian.PutUint32(b[24:], st.Mode)
	binary.BigEndian.PutUint32(b[36:], st.Size)
	return b
}

// Sign appends the checksum of body: SHA-256 when hashLen says so, SHA-1
// otherwise, or zeros when noSign is set.
func Sign(body []byte, hashLen int, noSign bool) []byte {
	out := slices.Clone(body)
	switch {
	case noSign:
		return append(out, make([]byte, hashLen)...)
	case hashLen == sha256.Size:
		sum := sha256.Sum256(body)
		return append(out, sum[:]...)
	}
	sum := sha1.Sum(body) //nolint:gosec // G401: git's index checksum
	return append(out, sum[:]...)
}

func commonPrefixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// Varint is git's encode_varint.
func Varint(v int) []byte {
	out := []byte{byte(v & 0x7f)}
	for v >>= 7; v > 0; v >>= 7 {
		v--
		out = append([]byte{0x80 | byte(v&0x7f)}, out...)
	}
	return out
}

// Extension is one index extension: its signature, size and data.
func Extension(sig string, data []byte) []byte {
	out := append([]byte(sig), binary.BigEndian.AppendUint32(nil, uint32(len(data)))...) //nolint:gosec // G115: test sizes
	return append(out, data...)
}
