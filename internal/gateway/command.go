package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Command limits. A model CLI that needs more is misconfigured.
const (
	maxCommandBytes   = 4096
	maxCommandArgs    = 64
	maxEnvNames       = 32
	minCommandTimeout = time.Second
	maxCommandTimeout = time.Hour
	minCommandOutput  = 1 << 10
	maxCommandOutput  = maxResponseBytes
	// commandScheme marks a command endpoint. It is never dialed: consent,
	// budget and egress.log key on it as they key on an HTTP origin.
	commandScheme = "command://"
)

// ErrCommand means a command model is misconfigured: an unsplittable
// command line, a program outside PATH or inside the repository, a bad
// environment name or limit. Nothing was run.
var ErrCommand = errors.New("invalid model command")

// baseEnv are the variables every model CLI gets, when set: enough to find
// its interpreter and its own login. Anything else, API keys included, is
// passed only when model.env names it.
var baseEnv = []string{
	"PATH", "HOME", "LANG", "LC_ALL",
	"SystemRoot", "SystemDrive", "WINDIR", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// CommandOptions configures NewCommand from the resolved config
// (model.run, model.env, model.timeout, model.max_output_bytes). The
// project file of the scanned repository cannot set Run or Env.
type CommandOptions struct {
	Run            string              // command line, split without a shell
	Env            []string            // names of extra variables to pass
	Getenv         func(string) string // os.Getenv in production
	Timeout        time.Duration       // per call, 1s to 1h
	MaxOutputBytes int                 // stdout cap, 1 KiB to 8 MiB
	RepoDir        string              // the scanned repository; a program inside it is refused
}

// Command is a model CLI: prompt on stdin, JSON on stdout. It is opaque like
// *Client: the only way to run it is EgressLog.Exec, so every run passes
// consent, the budget and egress.log.
type Command struct {
	path     string
	args     []string
	env      []string
	timeout  time.Duration
	maxOut   int
	endpoint string
	program  string
}

// NewCommand splits opts.Run, resolves the program on PATH and fixes the
// environment. A bare program name is looked up only in absolute PATH
// entries (exec.ErrDot is refused), so a file in the current directory, which
// is the repository during a scan, is never run; a resolved program inside
// RepoDir is refused too.
func NewCommand(opts CommandOptions) (*Command, error) {
	argv, err := splitCommandLine(opts.Run)
	if err != nil {
		return nil, err
	}
	if err := checkCommandLimits(opts); err != nil {
		return nil, err
	}
	path, err := resolveProgram(argv[0], opts.RepoDir)
	if err != nil {
		return nil, err
	}
	c := &Command{
		path: path, args: argv[1:], timeout: opts.Timeout, maxOut: opts.MaxOutputBytes,
		env: commandEnv(opts.Env, opts.Getenv), program: programName(path),
	}
	c.endpoint = commandEndpoint(c.program, path, c.args, opts.Env)
	return c, nil
}

// Endpoint is the command's consent and budget key, "command://<name>-<hash>".
// The hash covers the program path, the arguments and the env names, so any
// change asks for consent again and gets a fresh tool canary.
func (c *Command) Endpoint() string { return c.endpoint }

// Program is the program's base name without extension, such as "claude".
func (c *Command) Program() string { return c.program }

// Args returns a copy of the arguments after the program.
func (c *Command) Args() []string { return append([]string(nil), c.args...) }

func checkCommandLimits(opts CommandOptions) error {
	switch {
	case opts.Timeout < minCommandTimeout || opts.Timeout > maxCommandTimeout:
		return fmt.Errorf("%w: timeout must be %s to %s", ErrCommand, minCommandTimeout, maxCommandTimeout)
	case opts.MaxOutputBytes < minCommandOutput || opts.MaxOutputBytes > maxCommandOutput:
		return fmt.Errorf("%w: output cap must be %d to %d bytes", ErrCommand, minCommandOutput, maxCommandOutput)
	case len(opts.Env) > maxEnvNames:
		return fmt.Errorf("%w: at most %d env names", ErrCommand, maxEnvNames)
	case opts.Getenv == nil:
		return fmt.Errorf("%w: no Getenv", ErrCommand)
	}
	for _, name := range opts.Env {
		if !envName.MatchString(name) {
			return fmt.Errorf("%w: env name %q: want letters, digits and _", ErrCommand, name)
		}
	}
	return nil
}

// resolveProgram returns the absolute, symlink-free path of the program.
// A relative path with a separator would be relative to the repository.
func resolveProgram(name, repoDir string) (string, error) {
	if !filepath.IsAbs(name) && strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: program %q must be a name on PATH or an absolute path", ErrCommand, name)
	}
	found, err := exec.LookPath(name)
	if errors.Is(err, exec.ErrDot) {
		return "", fmt.Errorf("%w: program %q resolves to the current directory; only absolute PATH entries are searched", ErrCommand, name)
	}
	if err != nil {
		return "", fmt.Errorf("%w: program %q not found", ErrCommand, name)
	}
	real, err := filepath.EvalSymlinks(found)
	if err == nil {
		real, err = filepath.Abs(real)
	}
	if err != nil {
		return "", fmt.Errorf("%w: program %q: %w", ErrCommand, name, err)
	}
	if insideDir(real, repoDir) {
		return "", fmt.Errorf("%w: program %q is inside the scanned repository", ErrCommand, name)
	}
	return real, nil
}

// insideDir reports whether path is dir or below it, after resolving links
// in dir. An empty or unresolvable dir contains nothing.
func insideDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	real, err := filepath.EvalSymlinks(dir)
	if err == nil {
		real, err = filepath.Abs(real)
	}
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(real, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// commandEnv is baseEnv plus the declared names, each only when set.
// Values are read once, here, so a run cannot pick up later changes.
func commandEnv(names []string, getenv func(string) string) []string {
	var env []string
	for _, name := range append(append([]string(nil), baseEnv...), names...) {
		if v := getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// programName is the lowercase base name without a Windows extension.
func programName(path string) string {
	base := strings.ToLower(filepath.Base(path))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

func commandEndpoint(program, path string, args, envNames []string) string {
	h := sha256.New()
	for _, part := range append(append([]string{path}, args...), envNames...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return commandScheme + slug(program) + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// slug keeps [a-z0-9] and turns the rest into "-", so the endpoint is a
// plain host name in prompts, egress.log and policy files.
func slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 32 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	if out := strings.Trim(b.String(), "-"); out != "" {
		return out
	}
	return "cmd"
}

var commandKey = regexp.MustCompile(`^command://[a-z0-9-]{1,32}-[0-9a-f]{16}$`)

// isCommandKey reports whether s is a command endpoint as Endpoint returns it.
func isCommandKey(s string) bool { return commandKey.MatchString(s) }
