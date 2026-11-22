package verify

import (
	"strconv"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

// creep's payloads. They prove a flaw and nothing more: a delay, an empty
// table in the run's throwaway database, a read of the file creep planted
// in the app's container, an inert tag. None deletes, changes or reads
// application data.

// sqlSleepSeconds is how long the delay payload sleeps, and delayMargin
// how much longer than the baseline the payload request must take to
// count.
const (
	sqlSleepSeconds = 3
	delayMargin     = 2500 * time.Millisecond
)

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

// canaryFile is the file creep plants in the app's container, without
// its leading slash, so ../ steps lead to it from any directory.
var canaryFile = strings.TrimPrefix(sandbox.AppCanaryFile, "/")

// pathPayload is the path to creep's canary file in a style: ../ steps,
// the same with every slash percent-encoded, or absolute. Each is already
// in wire form, so it goes into a path, a form or a JSON string as it is.
func pathPayload(style string, depth int) value {
	var p string
	switch style {
	case "relative":
		p = strings.Repeat("../", depth) + canaryFile
	case "encoded":
		p = strings.Repeat("..%2f", depth) + strings.ReplaceAll(canaryFile, "/", "%2f")
	default:
		p = "/" + canaryFile
	}
	return value{wire: p, text: p}
}

// probe is what replaces the nonce placeholder: the nonce inside an inert
// tag, after both quotes, so it shows unescaped only where the app writes
// the input into its HTML as markup. An app that escapes any of the
// characters, as a safe one does, never shows it.
func probe(nonce string) string { return `'"><` + nonce + `>` }

// nonceValue is the probe encoded for a path or form (wire) and for a
// header or a text body (text); a JSON body escapes text.
func nonceValue(nonce string) value {
	p := probe(nonce)
	return value{wire: urlEncode(p), text: p}
}
