package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxInputBytes bounds each input so a huge payload or file list cannot stall CI.
const maxInputBytes = 32 << 20

// inputs name what the check reads: the event payload, the changed paths,
// AGENTS.md as it was on the base, and the checked-out tree.
type inputs struct {
	event, files, baseAgents, root string
}

func main() {
	var in inputs
	flag.StringVar(&in.event, "event", "", "pull_request event payload ($GITHUB_EVENT_PATH)")
	flag.StringVar(&in.files, "files", "", "changed paths, NUL-separated (git diff --name-only -z)")
	flag.StringVar(&in.baseAgents, "base-agents", "", "AGENTS.md on the base commit (git show HEAD^1:AGENTS.md)")
	flag.StringVar(&in.root, "root", ".", "checked-out pull request tree")
	flag.Parse()
	os.Exit(run(in, os.Stdout))
}

// run prints the problems and returns 0 when there are none, 1 when there
// are, and 2 when an input cannot be read, so the check fails closed.
func run(in inputs, out io.Writer) int {
	problems, err := check(in)
	if err != nil {
		fmt.Fprintln(out, "prcheck:", err)
		return 2
	}
	for _, p := range problems {
		fmt.Fprintln(out, "prcheck:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	fmt.Fprintln(out, "prcheck: ok")
	return 0
}

func check(in inputs) ([]string, error) {
	if in.event == "" || in.files == "" || in.baseAgents == "" {
		return nil, errors.New("-event, -files and -base-agents are required")
	}
	body, err := readBody(in.event)
	if err != nil {
		return nil, err
	}
	files, err := readFiles(in.files)
	if err != nil {
		return nil, err
	}
	base, err := readBounded(in.baseAgents)
	if err != nil {
		return nil, fmt.Errorf("read base AGENTS.md: %w", err)
	}
	problems, err := adrProblems(files, in.root, string(base))
	if err != nil {
		return nil, err
	}
	if docsOnlyClaimed(body) {
		problems = append(problems, docsOnlyProblems(files)...)
	}
	return problems, nil
}

// readBody returns the pull request body from a GitHub event payload. A
// payload without a pull request (another event) fails rather than passing
// unchecked; a pull request with no body claims nothing.
func readBody(name string) (string, error) {
	data, err := readBounded(name)
	if err != nil {
		return "", fmt.Errorf("read event: %w", err)
	}
	var ev struct {
		PullRequest *struct {
			Number int     `json:"number"`
			Body   *string `json:"body"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return "", fmt.Errorf("decode event: %w", err)
	}
	if ev.PullRequest == nil || ev.PullRequest.Number <= 0 {
		return "", errors.New("event has no pull request")
	}
	if ev.PullRequest.Body == nil {
		return "", nil
	}
	return *ev.PullRequest.Body, nil
}

// readFiles splits git's NUL-separated path list; -z keeps odd names intact.
func readFiles(name string) ([]string, error) {
	data, err := readBounded(name)
	if err != nil {
		return nil, fmt.Errorf("read changed files: %w", err)
	}
	var files []string
	for _, f := range strings.Split(string(data), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

func readBounded(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("%s is over %d bytes", name, maxInputBytes)
	}
	return data, nil
}
