package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// maxContextFiles bounds a build context; past it the build is not run.
const maxContextFiles = 20_000

// maxContextBytes bounds the bytes copied into a build context. A variable
// only so a test need not write 512 MiB.
var maxContextBytes = 512 << 20

// leftOutNames are path components never copied into a build context: the
// repository's .env files (the app gets only creep's synthetic env,
// appEnv),
// git's and creep's state, and files where credentials live. Matched
// case-insensitively; .env matches every name that starts with it.
var leftOutNames = map[string]bool{
	".git": true, ".creep": true,
	".ssh": true, ".aws": true, ".azure": true, ".kube": true, ".gnupg": true,
	".netrc": true, "_netrc": true, ".git-credentials": true, ".npmrc": true, ".pypirc": true,
}

// leftOut reports a path the build context never holds.
func leftOut(p string) bool {
	for _, part := range strings.Split(strings.ToLower(p), "/") {
		if leftOutNames[part] || strings.HasPrefix(part, ".env") {
			return true
		}
	}
	return false
}

// stageContext copies the context's files from the repository, through
// the scan's reader, into a fresh directory in the sandbox's work
// directory, and returns it. The runtime builds from that copy, never from
// the repository: a link cannot point the build at a host file, a compose
// context cannot leave the repository, and the files leftOut names never
// reach the builder. Executable bits are not in the file list, so a file
// that starts like a script or an ELF binary is written executable.
func (s *Sandbox) stageContext(ctx context.Context, repo Repo, plan buildPlan) (string, *refusal, error) {
	files := contextFiles(repo.Paths, plan.context)
	if len(files) > maxContextFiles {
		return "", refuse(BuildContextRefused, "too_many_files"), nil
	}
	dir := filepath.Join(s.work, "build-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", refuse(BuildContextRefused, "work_directory"), nil
	}
	total := 0
	for _, p := range files {
		if ctx.Err() != nil {
			return "", nil, fmt.Errorf("sandbox build: stage context: %w", ctx.Err())
		}
		data, err := repo.Read(p)
		if err != nil {
			return "", refuse(BuildContextRefused, "unreadable_file"), nil
		}
		if total += len(data); total > maxContextBytes {
			return "", refuse(BuildContextRefused, "too_large"), nil
		}
		if err := writeStaged(dir, relTo(plan.context, p), data); err != nil {
			return "", refuse(BuildContextRefused, "write"), nil
		}
	}
	return dir, nil, nil
}

// contextFiles are the clean repository paths below dir, minus leftOut.
func contextFiles(paths []string, dir string) []string {
	var files []string
	for _, p := range cleanPaths(paths) {
		if (dir == "." || strings.HasPrefix(p, dir+"/")) && !leftOut(relTo(dir, p)) && !leftOut(p) {
			files = append(files, p)
		}
	}
	return files
}

func relTo(dir, p string) string {
	if dir == "." {
		return p
	}
	return strings.TrimPrefix(p, dir+"/")
}

// writeStaged creates one file below root. Every directory and file is new
// (exclusive create), so nothing already there, such as a link, is
// followed.
func writeStaged(root, rel string, data []byte) error {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return fmt.Errorf("staged path %q is not local", rel)
	}
	target := filepath.Join(root, filepath.FromSlash(rel))
	if err := mkdirBelow(root, path.Dir(rel)); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if bytes.HasPrefix(data, []byte("#!")) || bytes.HasPrefix(data, []byte("\x7fELF")) {
		mode = 0o755
	}
	// G304/G302: target is below the sandbox's own 0700 work directory,
	// and the builder, which may run as another user, must read it.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304, G302, see above
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// mkdirBelow creates rel's directories under root one at a time, each a
// real directory, never through a link.
func mkdirBelow(root, rel string) error {
	if rel == "." {
		return nil
	}
	dir := root
	for _, part := range strings.Split(rel, "/") {
		dir = filepath.Join(dir, part)
		err := os.Mkdir(dir, 0o755) //nolint:gosec // G301: the builder must traverse it; the work directory is 0700
		if err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("staged directory %q is not a directory", rel)
		}
	}
	return nil
}
