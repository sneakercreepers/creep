// Command settingsdrift reports where a live repository setting differs from
// its file in .github/rulesets or .github/settings.
//
// make repo-settings-check fetches each live setting with gh and passes the
// file and the fetched JSON here, so this command compares two local files
// and needs no network (AGENTS.md invariant 1). Every key the file sets must
// be present live with the same value; a live key the file does not set is
// ignored, because GitHub adds read-only fields (id, links, timestamps) and
// defaults. Arrays must have the same length and each file item must match
// a different live item in any order, because GitHub may reorder rules and
// checks. So an extra live rule, check or bypass actor is drift, while an
// unmanaged key inside a managed object is not (architecture.md §9).
//
// It exits 0 when the setting matches, 1 on drift and 2 when an input is
// missing or unreadable, so the check fails closed.
package main
