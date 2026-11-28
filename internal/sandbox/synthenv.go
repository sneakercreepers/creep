package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// envFileName is the file appEnv mounts in the app's working directory,
// where frameworks look for one.
const envFileName = ".env"

// appEnv is the synthetic env of the app and its migrate step: the run
// database's connection settings once StartDatabase has one ready, else
// nothing. Every value is creep's: the host is the database's name on the
// run network and the password a fresh random placeholder, so no real
// secret is ever inside a container, and nothing comes from the host's or
// the repository's environment (the build context never holds a .env,
// leftOut). The same variables go into the container's environment and,
// for an app that reads a file instead, into a .env file mounted
// read-only in its working directory.
func (s *Sandbox) appEnv(workdir string) (map[string]string, Mount, error) {
	env := map[string]string{}
	if db, ok := s.readyDatabase(); ok {
		env = databaseEnv(db)
	}
	file, err := s.writeEnvFile(env)
	if err != nil {
		return nil, Mount{}, err
	}
	return env, Mount{Source: file, Target: path.Join(workdir, envFileName)}, nil
}

// databaseEnv names the database the way most drivers and frameworks
// read it: one URL, and libpq's own variables.
func databaseEnv(db Database) map[string]string {
	return map[string]string{
		"DATABASE_URL": db.URL(),
		"PGHOST":       db.Host,
		"PGPORT":       strconv.Itoa(db.Port),
		"PGUSER":       db.User,
		"PGPASSWORD":   db.Password,
		"PGDATABASE":   db.Name,
	}
}

// writeEnvFile writes env, sorted, as a .env file in a fresh directory of
// the work directory and returns its path, to mount read-only. Names
// follow the env-variable rule and values hold no line break.
func (s *Sandbox) writeEnvFile(env map[string]string) (string, error) {
	lines, err := envLines(env)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.work, "env-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	file := filepath.Join(dir, envFileName)
	// G306: the container user (65534) must read it; the work directory is
	// 0700, so no other host user can reach it, and it holds no secret.
	if err := os.WriteFile(file, []byte(lines), 0o644); err != nil { //nolint:gosec // G306, see above
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	return file, nil
}

// runEnvPrefix starts the name of the env file the runtime CLI reads for
// one container; the container's own name follows.
const runEnvPrefix = "run-env-"

// writeRunEnv writes a container's env as the file its `run` reads with
// --env-file, so no value is on the CLI's command line. The file is
// creep's own, never the repository's: created new (O_EXCL) in the 0700
// work directory, 0600, since only the CLI, as this user, reads it. Docker
// and Podman read a line as NAME=value with the value verbatim; Podman
// may unquote a value that starts with a quote, so none may.
func (s *Sandbox) writeRunEnv(name string, env map[string]string) (string, error) {
	lines, err := envLines(env)
	if err != nil {
		return "", err
	}
	file := filepath.Join(s.workReal, runEnvPrefix+name)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: a new file in the sandbox's own work directory
	if err != nil {
		return "", fmt.Errorf("container env: %w", err)
	}
	_, err = f.WriteString(lines)
	if err = errors.Join(err, f.Close()); err != nil {
		_ = os.Remove(file) //nolint:gosec // G703: the file just created in the sandbox's own work directory
		return "", fmt.Errorf("container env: %w", err)
	}
	return file, nil
}

// removeRunEnv deletes the env file of a container whose `run` returned.
func (s *Sandbox) removeRunEnv(name string) {
	_ = os.Remove(filepath.Join(s.workReal, runEnvPrefix+name)) //nolint:gosec // G703: name is creep's own container name, in the work directory
}

// envLines renders env sorted, one NAME=value line each. Names follow the
// env-variable rule; values hold no line break, are valid UTF-8 (Docker
// refuses a file that is not) and start with no quote.
func envLines(env map[string]string) (string, error) {
	if len(env) > maxEnv {
		return "", fmt.Errorf("synthetic env: %d names: %w", len(env), ErrSpec)
	}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, name := range names {
		v := env[name]
		if !envName.MatchString(name) || !plainValue(v) || !utf8.ValidString(v) || strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'") || isProxyVar(name) {
			return "", fmt.Errorf("synthetic env: name %q: %w", name, ErrSpec)
		}
		b.WriteString(name + "=" + v + "\n")
	}
	return b.String(), nil
}
