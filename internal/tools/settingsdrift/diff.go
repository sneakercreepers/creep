package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf16"
)

// diff returns one line per place where got does not hold want.
func diff(path string, want, got any) []string {
	switch w := want.(type) {
	case map[string]any:
		return diffObject(path, w, got)
	case []any:
		return diffArray(path, w, got)
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	return mismatch(path, want, got)
}

func diffObject(path string, want map[string]any, got any) []string {
	g, ok := got.(map[string]any)
	if !ok {
		return mismatch(path, want, got)
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []string
	for _, k := range keys {
		v, ok := g[k]
		if !ok {
			out = append(out, fmt.Sprintf("%s: file %s, live has no such key", at(path+"."+k), show(want[k])))
			continue
		}
		out = append(out, diff(path+"."+k, want[k], v)...)
	}
	return out
}

// diffArray matches items in any order. Items left unmatched on both sides
// are paired in order so a changed rule reports the key that changed.
func diffArray(path string, want []any, got any) []string {
	g, ok := got.([]any)
	if !ok {
		return mismatch(path, want, got)
	}
	wantLeft, gotLeft := unmatched(want, g)
	if len(want) != len(g) {
		return []string{fmt.Sprintf("%s: file has %d items, live %d; only in file %s, only live %s",
			at(path), len(want), len(g), show(pick(want, wantLeft)), show(pick(g, gotLeft)))}
	}
	var out []string
	for i, wi := range wantLeft {
		out = append(out, diff(fmt.Sprintf("%s[%d]", path, wi), want[wi], g[gotLeft[i]])...)
	}
	return out
}

// unmatched pairs each file item with the first unused live item that holds
// it and returns the indexes left over on each side.
func unmatched(want, got []any) (wantLeft, gotLeft []int) {
	used := make([]bool, len(got))
	for i, w := range want {
		j := -1
		for k, g := range got {
			if !used[k] && len(diff("", w, g)) == 0 {
				j = k
				break
			}
		}
		if j < 0 {
			wantLeft = append(wantLeft, i)
			continue
		}
		used[j] = true
	}
	for k := range got {
		if !used[k] {
			gotLeft = append(gotLeft, k)
		}
	}
	return wantLeft, gotLeft
}

func pick(items []any, idx []int) []any {
	out := make([]any, 0, len(idx))
	for _, i := range idx {
		out = append(out, items[i])
	}
	return out
}

func mismatch(path string, want, got any) []string {
	return []string{fmt.Sprintf("%s: file %s, live %s", at(path), show(want), show(got))}
}

func at(path string) string {
	if path == "" {
		return "."
	}
	return path
}

// show prints a value as JSON; ascii keeps live text from GitHub from
// faking output lines or hiding characters on the terminal.
func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unprintable>"
	}
	return ascii(string(b))
}

// ascii escapes every rune outside printable ASCII as \uXXXX, which keeps
// JSON valid and plain text readable.
func ascii(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
			continue
		}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}
