//go:build windows

package calibrate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"github.com/sneakercreepers/creep/internal/state"
)

const (
	fsctlSetReparsePoint = 0x000900A4 // FSCTL_SET_REPARSE_POINT
	reparseTagMountPoint = 0xA0000003 // IO_REPARSE_TAG_MOUNT_POINT, a junction
)

// A calibrations/ directory that is a junction, the link Windows makes
// without privilege, fails closed like a symbolic link (#180): load, save
// and RunCached refuse it, naming the path, before any model call and
// with or without --recalibrate, and the target is left untouched.
func TestJunctionCacheDirFailsBeforeCalls(t *testing.T) {
	for _, recalibrate := range []bool{false, true} {
		t.Run("recalibrate="+strconv.FormatBool(recalibrate), func(t *testing.T) {
			e := newCacheEnv(t)
			dir := filepath.Join(e.dir, "calibrations")
			target := t.TempDir()
			junction(t, target, dir)
			opts := e.options(t, calibrated)
			opts.Recalibrate = recalibrate
			_, runErr := RunCached(context.Background(), opts)
			_, _, loadErr := e.store.LoadCalibration(strings.Repeat("a", 64))
			saveErr := e.store.SaveCalibration(strings.Repeat("a", 64), state.Calibration{At: calibrated, Result: json.RawMessage(`{}`)})
			for op, err := range map[string]error{"RunCached": runErr, "load": loadErr, "save": saveErr} {
				if !errors.Is(err, state.ErrUnsafePath) || !strings.Contains(err.Error(), strconv.Quote(dir)) {
					t.Errorf("%s: err = %v; want ErrUnsafePath naming %q", op, err, dir)
				}
			}
			if len(e.model.calls) != 0 {
				t.Errorf("%d model calls before failing", len(e.model.calls))
			}
			if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
				t.Errorf("junction target holds %v (%v); want it untouched", entries, err)
			}
		})
	}
}

// junction makes link a junction to the directory target. The standard
// library cannot make one and tests may not run mklink (make budget), so it
// sets the reparse point itself, as mklink /J and internal/cli's linkDir do.
func junction(t *testing.T, target, link string) {
	t.Helper()
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
	buf := mountPointBuffer(target)
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
