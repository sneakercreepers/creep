package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"time"
)

// MaxCalibrationBytes caps one stored calibration file. A result is a few
// KiB of counts and enums; a larger file is refused as corrupt.
const MaxCalibrationBytes = 64 << 10

const calibrationsDir = "calibrations"

// calibrationDomain keeps a calibration line from verifying as a cache entry
// or a run line, and the other way round.
var calibrationDomain = []byte("creep calibration v1\x00")

var calibrationKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Calibration is one stored model calibration: the result as JSON, owned by
// internal/calibrate, and when it was measured.
type Calibration struct {
	At     time.Time
	Result json.RawMessage
}

// calibrationEntry is one calibrations/<key>.json file, the v1 contract
// (TestV1FixtureDecodes).
type calibrationEntry struct {
	V      int             `json:"v"`
	Key    string          `json:"key"`
	At     time.Time       `json:"at"`
	Result json.RawMessage `json:"result"`
	MAC    string          `json:"mac,omitempty"` // HMAC-SHA256 of the line; always the last field
}

// CheckCalibrationDir refuses a calibrations/ entry that is a link, a
// junction, a file or writable by others. A missing directory is fine. The
// error is ErrUnsafePath and names the absolute path to remove: no
// calibration can replace the directory, so retrying with --recalibrate
// would fail the same way (#180).
func (s *Store) CheckCalibrationDir() error {
	_, err := checkDir(calibrationsDir, s.root.Lstat)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("calibration cache directory %q is unsafe; remove it and creep recreates it: %w", s.abs(calibrationsDir), err)
}

func calibrationFile(key string) (string, error) {
	if !calibrationKeyPattern.MatchString(key) {
		return "", fmt.Errorf("calibration key: %w", ErrInvalidID)
	}
	return path.Join(calibrationsDir, key+".json"), nil
}

// LoadCalibration returns the calibration stored under key, a hex SHA-256
// the caller derives from what was measured. A missing file is not an
// error. A file this user's creep did not write is ErrCorrupt wrapping
// ErrUnauthenticated; one written by a newer creep is ErrUnsupportedVersion.
func (s *Store) LoadCalibration(key string) (Calibration, bool, error) {
	name, err := calibrationFile(key)
	if err != nil {
		return Calibration{}, false, err
	}
	if err := s.CheckCalibrationDir(); err != nil {
		return Calibration{}, false, err
	}
	data, err := s.readBounded(name, MaxCalibrationBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return Calibration{}, false, nil
	}
	if err != nil {
		return Calibration{}, false, fmt.Errorf("calibration: %w", err)
	}
	c, err := decodeCalibration(data, key, s.key)
	if err != nil {
		return Calibration{}, false, fmt.Errorf("calibration %s: %w", name, err)
	}
	return c, true, nil
}

func decodeCalibration(data []byte, key string, mk macKey) (Calibration, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte("\n")) != 1 {
		return Calibration{}, fmt.Errorf("not one complete line: %w", ErrCorrupt)
	}
	body, err := verify(mk, calibrationDomain, data[:len(data)-1])
	if err != nil {
		return Calibration{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	var e calibrationEntry
	if err := json.Unmarshal(body, &e); err != nil {
		return Calibration{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if e.V > Version {
		return Calibration{}, fmt.Errorf("v %d: %w", e.V, ErrUnsupportedVersion)
	}
	if e.V < 1 || e.Key != key || e.At.IsZero() || len(e.Result) == 0 || e.Result[0] != '{' {
		return Calibration{}, fmt.Errorf("version, key, time or result mismatch: %w", ErrCorrupt)
	}
	return Calibration{At: e.At, Result: e.Result}, nil
}

// SaveCalibration stores c under key atomically, replacing any earlier one.
// c.Result must be a JSON object holding only counts, enums and hashes.
func (s *Store) SaveCalibration(key string, c Calibration) error {
	name, err := calibrationFile(key)
	if err != nil {
		return err
	}
	if c.At.IsZero() || !json.Valid(c.Result) || !bytes.HasPrefix(bytes.TrimSpace(c.Result), []byte("{")) {
		return fmt.Errorf("calibration: need a time and a JSON object: %w", ErrInvalidID)
	}
	body, err := json.Marshal(calibrationEntry{V: Version, Key: key, At: c.At.UTC(), Result: c.Result})
	if err != nil {
		return fmt.Errorf("calibration: %w", err)
	}
	signed, err := sign(s.key, calibrationDomain, body)
	if err != nil {
		return fmt.Errorf("calibration: %w", err)
	}
	line := append(signed, '\n')
	if len(line) > MaxCalibrationBytes {
		return fmt.Errorf("calibration: %d bytes: %w", len(line), ErrTooLarge)
	}
	if err := s.CheckCalibrationDir(); err != nil {
		return err
	}
	if err := s.ensureDir(calibrationsDir); err != nil {
		return err
	}
	return s.writeAtomic(name, line)
}
