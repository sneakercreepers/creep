package discover

import (
	"fmt"
	"slices"
	"strings"
)

// SinkKindsOn returns the sink kinds the tripwire table finds on line, in
// kind order, each once. It reads the same cross-language table the scan
// does, so a caller that needs a sink's kind (`creep recipe lint`) needs no
// language rule of its own. Only the first line of line is read.
func SinkKindsOn(line string) ([]SinkKind, error) {
	rows, err := loadTripwire()
	if err != nil {
		return nil, fmt.Errorf("tripwire: %w", err)
	}
	line, _, _ = strings.Cut(line, "\n")
	var kinds []SinkKind
	for _, r := range rows {
		if r.matches([]byte(line)) {
			kinds = append(kinds, r.kind)
		}
	}
	slices.Sort(kinds)
	return slices.Compact(kinds), nil
}
