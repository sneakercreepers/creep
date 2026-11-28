package cli

import (
	"io/fs"
	"path"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// codeBytes weighs a walk: the bytes of the files discovery would open
// (discover.MaybeSource) that it is given, besides .gitignore files, and
// of those listed vendor. A vendor file whose size cannot be read
// (unsized) weighs more than any read.
type codeBytes struct {
	read, vendor int64
	unsized      bool
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
		c.read += info.Size()
	}
}

// exceeded is the vendor bound (#380): vendor hides more code bytes than
// discovery reads. The repository's git index and ignore files are its own
// bytes, so an archive can plant both and list most of its code vendor
// behind one decoy file; this keeps such a run from passing as complete.
func (c codeBytes) exceeded() bool {
	return c.unsized || c.vendor > c.read
}

// boundVendor lists every vendor file vendor_exceeds_read, a gap, when
// the bound is exceeded: the files stay unread and listed, and the run is
// incomplete (exit 4) instead of complete behind them.
func boundVendor(files repoFiles, weight codeBytes) repoFiles {
	if !weight.exceeded() {
		return files
	}
	for i, g := range files.gaps {
		if g.Reason == report.SkipVendor {
			files.gaps[i].Reason = report.SkipVendorExceedsRead
		}
	}
	return files
}
