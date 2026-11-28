package cli

import (
	"context"
	"io/fs"
	"os"
	"path"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// codeBytes weighs a walk: the bytes of the files listed vendor that
// discovery would open (discover.MaybeSource), and the files it is given,
// to be weighed only if the bound applies. A vendor file whose size cannot
// be read (unsized) weighs more than any read. .gitignore files count on
// neither side.
type codeBytes struct {
	vendor  int64
	unsized bool
	given   []sizedFile
}

type sizedFile struct {
	rel  string
	size int64
}

// add weighs the walked file rel: vendor or given to discovery.
func (c *codeBytes) add(rel string, d fs.DirEntry, vendor bool) {
	if !discover.MaybeSource(rel) || path.Base(rel) == ".gitignore" {
		return
	}
	info, err := d.Info()
	switch {
	case vendor && err != nil:
		c.unsized = true
	case vendor:
		c.vendor += info.Size()
	case err == nil:
		c.given = append(c.given, sizedFile{rel, info.Size()})
	}
}

// exceeded is the vendor bound (#380): vendor hides more code bytes than
// discovery reads. Only a given file discovery reads whole as text counts
// as read (discover.ReadsAsText, at most redact.MaxFileBytes), so a large
// binary or data file cannot pad the read side. Its head is read only
// until the read bytes reach the vendor bytes. Past the scan deadline, or
// when a head cannot be read, the file does not count (fail closed).
func (c codeBytes) exceeded(ctx context.Context, root *os.Root) bool {
	if c.unsized {
		return true
	}
	var read int64
	for _, f := range c.given {
		if read >= c.vendor {
			return false
		}
		if ctx.Err() != nil {
			return true
		}
		if f.size <= redact.MaxFileBytes && readsAsText(root, f.rel) {
			read += f.size
		}
	}
	return c.vendor > read
}

func readsAsText(root *os.Root, rel string) bool {
	head, err := readHeadInRoot(root, rel, discover.HeadBytes)
	return err == nil && discover.ReadsAsText(rel, head)
}

// boundVendor lists every vendor file vendor_exceeds_read, a gap, when
// the bound is exceeded: the files stay unread and listed, and the run is
// incomplete (exit 4) instead of complete behind them.
func boundVendor(ctx context.Context, root *os.Root, files repoFiles, weight codeBytes) repoFiles {
	if !hasVendor(files.gaps) || !weight.exceeded(ctx, root) {
		return files
	}
	for i, g := range files.gaps {
		if g.Reason == report.SkipVendor {
			files.gaps[i].Reason = report.SkipVendorExceedsRead
		}
	}
	return files
}
