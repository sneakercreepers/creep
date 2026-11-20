//go:build windows

package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unicode/utf16"
)

const (
	fsctlSetReparsePoint = 0x000900A4 // FSCTL_SET_REPARSE_POINT
	reparseTagMountPoint = 0xA0000003 // IO_REPARSE_TAG_MOUNT_POINT, a junction
)

// linkDir makes link a junction to the directory target: the directory
// link Windows makes without privilege, unlike a symbolic link. The
// standard library cannot make one and tests here may not run mklink
// (make budget), so it sets the reparse point itself, as mklink /J does.
func linkDir(t *testing.T, target, link string) {
	t.Helper()
	abs, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	name, err := syscall.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Skipf("cannot open %s to make a junction here: %v", link, err)
	}
	defer syscall.CloseHandle(h) //nolint:errcheck // a test handle; the junction is already set
	buf := mountPointBuffer(abs)
	var n uint32
	if err := syscall.DeviceIoControl(h, fsctlSetReparsePoint, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil { //nolint:gosec // G115: a short test path
		t.Skipf("cannot make a junction here: %v", err)
	}
}

// mountPointBuffer is the REPARSE_DATA_BUFFER of a junction to target: an
// 8-byte header, four name offsets and lengths, then the NT name and the
// printed name, each ending in a NUL.
func mountPointBuffer(target string) []byte {
	subst := utf16.Encode([]rune(`\??\` + target))
	printed := utf16.Encode([]rune(target))
	names := append(append(append(subst, 0), printed...), 0)
	buf := make([]byte, 16+2*len(names))
	le := binary.LittleEndian
	le.PutUint32(buf[0:], reparseTagMountPoint)
	le.PutUint16(buf[4:], uint16(len(buf)-8))      //nolint:gosec // G115: a short test path
	le.PutUint16(buf[10:], uint16(2*len(subst)))   //nolint:gosec // G115: a short test path
	le.PutUint16(buf[12:], uint16(2*len(subst)+2)) //nolint:gosec // G115: a short test path
	le.PutUint16(buf[14:], uint16(2*len(printed))) //nolint:gosec // G115: a short test path
	for i, c := range names {
		le.PutUint16(buf[16+2*i:], c)
	}
	return buf
}
