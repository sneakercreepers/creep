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

func main() {
	eventPath := flag.String("event", "", "pull_request event payload ($GITHUB_EVENT_PATH)")
	filesPath := flag.String("files", "", "changed paths, NUL-separated (git diff --name-only -z)")
	flag.Parse()
	os.Exit(run(*eventPath, *filesPath, os.Stdout))
}

// run prints the problems and returns 0 when there are none, 1 when there
// are, and 2 when an input cannot be read, so the check fails closed.
func run(eventPath, filesPath string, out io.Writer) int {
	problems, err := check(eventPath, filesPath)
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

func check(eventPath, filesPath string) ([]string, error) {
	if eventPath == "" || filesPath == "" {
		return nil, errors.New("both -event and -files are required")
	}
	pr, err := readEvent(eventPath)
	if err != nil {
		return nil, err
	}
	files, err := readFiles(filesPath)
	if err != nil {
		return nil, err
	}
	problems := bodyProblems(pr)
	if len(tickedItems(pr.body)[docsBox]) > 0 {
		problems = append(problems, docsOnlyProblems(files)...)
	}
	return problems, nil
}

// readEvent decodes the pull request from a GitHub event payload. A payload
// without one (another event) fails rather than passing unchecked.
func readEvent(name string) (pullRequest, error) {
	data, err := readBounded(name)
	if err != nil {
		return pullRequest{}, fmt.Errorf("read event: %w", err)
	}
	var ev struct {
		PullRequest *struct {
			Number int     `json:"number"`
			Body   *string `json:"body"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return pullRequest{}, fmt.Errorf("decode event: %w", err)
	}
	if ev.PullRequest == nil || ev.PullRequest.Number <= 0 || ev.Repository.FullName == "" {
		return pullRequest{}, errors.New("event has no pull request number or repository")
	}
	pr := pullRequest{repo: ev.Repository.FullName, number: ev.PullRequest.Number}
	if ev.PullRequest.Body != nil {
		pr.body = *ev.PullRequest.Body
	}
	return pr, nil
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
