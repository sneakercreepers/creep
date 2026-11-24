package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/report"
)

// defaultBaselineFile is where `creep accept` writes when --baseline is not
// given. scan reads a baseline only when --baseline names one (ADR 0022).
const defaultBaselineFile = "creep-baseline.json"

// today is the baseline's clock; tests fix it.
func (d scanDeps) today() time.Time {
	if d.date == nil {
		return time.Now()
	}
	return d.date()
}

// checkBaselineFlags keeps the baseline flags on the commands that use
// them, so none is silently ignored (#27). There is no config key: neither
// the project file nor any other layer can name or move a baseline.
func checkBaselineFlags(cmd string, o globalOptions) error {
	switch {
	case o.explicit["baseline"] && o.baseline == "":
		return errors.New("--baseline needs a file path")
	case o.explicit["baseline"] && cmd != "scan" && cmd != "resume" && cmd != "accept":
		return errors.New("--baseline is only for scan, resume and accept")
	case o.baselineWrite && cmd != "scan" && cmd != "resume":
		return errors.New("--baseline-write is only for scan and resume")
	case o.baselineWrite && o.baseline == "":
		return errors.New("--baseline-write needs --baseline <file>, the file it writes")
	case (o.explicit["expires"] || o.explicit["reason"]) && cmd != "accept":
		return errors.New("--expires and --reason are only for accept")
	}
	return nil
}

// scanBaseline is the baseline a scan reads (--baseline) and may rewrite
// (--baseline-write); nil when the scan has none.
type scanBaseline struct {
	path  string
	file  *baseline.File
	write bool
	today time.Time
}

// loadScanBaseline reads --baseline before the run opens any state or
// calls a model. A file that is missing (unless the run writes it), a
// link, too large or malformed exits 2: a baseline nobody can read must
// not turn into a scan with no baseline, or with half of one.
func loadScanBaseline(o globalOptions, today time.Time) (*scanBaseline, error) {
	if o.baseline == "" {
		return nil, nil
	}
	b, err := readBaselineFile(o.baseline, today, o.baselineWrite)
	if err != nil {
		return nil, err
	}
	return &scanBaseline{path: o.baseline, file: b, write: o.baselineWrite, today: today}, nil
}

func readBaselineFile(path string, today time.Time, missingOK bool) (*baseline.File, error) {
	if err := checkBaselinePath(path); err != nil {
		return nil, err
	}
	// Opened like the project file: the repository may plant a link here.
	data, err := readConfigWith(openProjectConfig, "--baseline", path)
	if errors.Is(err, errNoFile) && missingOK {
		return &baseline.File{Version: baseline.Version}, nil
	}
	if err != nil {
		return nil, err
	}
	b, err := baseline.Parse(data, today)
	if err != nil {
		return nil, fmt.Errorf("--baseline %q: %w", path, err)
	}
	return b, nil
}

// checkBaselinePath vets --baseline before anything touches the path: no
// UNC share or device path, whose lookup alone is network traffic on
// Windows, and nothing under /proc, /sys or /dev (checkConfigPath). For a
// path inside the working directory, no directory above the file may be a
// link or junction: the repository could plant one to move the read or
// the write out of the tree, past the final-name checks.
func checkBaselinePath(path string) error {
	if err := checkConfigPath("--baseline", path); err != nil {
		return err
	}
	dir := filepath.Dir(filepath.Clean(path))
	if !filepath.IsLocal(dir) {
		return nil // absolute or above the working directory: the operator's own path
	}
	for ; dir != "."; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil // a missing directory fails the open or write with its own error
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
			return fmt.Errorf("--baseline %q: a directory above the file is a link or special file", path)
		}
	}
	return nil
}

// fingerprint gives each probable or verified finding the reader decided
// its fingerprint, from the redacted sink line of the slice behind it.
func fingerprint(findings []report.Finding, kept map[int]reader.Slice) {
	for i := range findings {
		f := &findings[i]
		s, ok := kept[i]
		if ok && (f.Status == report.StatusProbable || f.Status == report.StatusVerified) {
			f.Fingerprint = baseline.Fingerprint(f.Class, f.Path, baseline.SinkAnchor(s.Sink))
		}
	}
}

// apply suppresses the findings b's live entries match.
func (b *scanBaseline) apply(findings []report.Finding) report.BaselineUse {
	if b == nil {
		return report.BaselineUse{}
	}
	return baseline.Apply(findings, b.file, b.today)
}

// save rewrites the baseline after the run, when --baseline-write asked,
// and says on stderr what it wrote. A report a baseline must not come from
// is refused: nothing is written and the error is returned.
func (b *scanBaseline) save(w io.Writer, rep *report.Report) error {
	if b == nil || !b.write {
		return nil
	}
	if err := baseline.Writable(rep); err != nil {
		return fmt.Errorf("--baseline-write: nothing written: %w", err)
	}
	out, err := baseline.Refresh(b.file, rep.Findings, b.today)
	if err == nil {
		err = writeBaselineFile(b.path, out)
	}
	if err != nil {
		return fmt.Errorf("--baseline-write: %w", err)
	}
	accepted := 0
	for _, e := range out.Entries {
		if e.Kind == report.SuppressAccepted {
			accepted++
		}
	}
	fmt.Fprintf(w, "baseline: wrote %d entries to %s (%d baseline, expiring in %d days; %d accepted risks kept)\n",
		len(out.Entries), escapeControl(b.path), len(out.Entries)-accepted, baseline.BaselineDays, accepted)
	return nil
}

// writeBaselineFile replaces path with b, never through a link: a link or
// special file there is refused, and the new file is written beside it
// under a random name and renamed over it, which replaces a link swapped
// in after the check instead of writing through it.
func writeBaselineFile(path string, b *baseline.File) error {
	data, err := b.Marshal()
	if err != nil {
		return err
	}
	if err := checkBaselinePath(path); err != nil {
		return err
	}
	if _, err := lstatNoLink("--baseline", path); err != nil && !errors.Is(err, errNoFile) {
		return err
	}
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return configError("--baseline", path, err)
	}
	defer root.Close()
	tmp, err := writeTemp(root, name, data)
	if err != nil {
		return configError("--baseline", path, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return configError("--baseline", path, err)
	}
	return nil
}

func writeTemp(root *os.Root, name string, data []byte) (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	tmp := "." + name + "." + hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// printBaseline states how the scan used its baseline; nothing without
// one. Every value is a count report.New checked.
func printBaseline(w io.Writer, rep *report.Report) {
	if text := rep.Baseline.Text(rep.Findings); text != "" {
		fmt.Fprintln(w, text)
	}
}

// suppressionNote is a suppressed finding's note in the text summary.
func suppressionNote(f report.Finding) string {
	if !f.Suppressed() {
		return ""
	}
	return "  " + escapeControl(f.Suppression.Text())
}
