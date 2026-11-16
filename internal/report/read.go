package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// maxReportBytes caps a report read back by ReadJSON. A real report stays
// far below it; a larger file is refused, not truncated.
const maxReportBytes = 64 << 20

// ReadJSON decodes a JSON report written by WriteJSON, for `creep why`. It
// is strict (one value, no unknown fields, the current schema_version) and
// checks every finding as New does, so an edited or planted report fails
// instead of feeding arbitrary values to the caller. Strings in it still
// come from the scanned repository: escape them before printing.
func ReadJSON(r io.Reader) (*Report, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if len(data) > maxReportBytes {
		return nil, fmt.Errorf("%w: report over %d bytes", ErrInvalid, maxReportBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rep Report
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the report", ErrInvalid)
	}
	if rep.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d, want %d", ErrInvalid, rep.SchemaVersion, SchemaVersion)
	}
	if _, err := checkFindings(rep.Findings); err != nil {
		return nil, err
	}
	return &rep, nil
}

// Finding returns the finding with id, if the report has one.
func (r *Report) Finding(id string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}
