package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxInputBytes bounds each input; a ruleset or setting is a few KiB.
const maxInputBytes = 1 << 20

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run compares the file (args[1]) with the live setting (args[2]) and
// prints one line per drift, labeled with args[0].
func run(args []string, out io.Writer) int {
	if len(args) != 3 {
		fmt.Fprintln(out, "usage: settingsdrift <label> <file.json> <live.json>")
		return 2
	}
	want, err := readJSON(args[1])
	if err != nil {
		fmt.Fprintln(out, "settingsdrift:", ascii(err.Error()))
		return 2
	}
	got, err := readJSON(args[2])
	if err != nil {
		fmt.Fprintln(out, "settingsdrift:", ascii(err.Error()))
		return 2
	}
	drifts := diff("", want, got)
	for _, d := range drifts {
		fmt.Fprintf(out, "drift %s: %s\n", ascii(args[0]), d)
	}
	if len(drifts) > 0 {
		return 1
	}
	fmt.Fprintf(out, "ok %s\n", ascii(args[0]))
	return 0
}

// readJSON decodes exactly one JSON value from a regular file. Numbers stay
// json.Number so ids and counts compare exactly.
func readJSON(name string) (any, error) {
	data, err := readRegular(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: more than one JSON value", name)
	}
	return v, nil
}

// readRegular refuses links, directories and FIFOs before opening, so a
// misplaced path fails instead of blocking.
func readRegular(name string) ([]byte, error) {
	info, err := os.Lstat(name) //nolint:gosec // G703: comparing the files the maintainer names is the point; Lstat reads no content
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(name) //nolint:gosec // G703: as above, and only after Lstat found a regular file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxInputBytes)
	}
	return data, nil
}
