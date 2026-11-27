package sandbox

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
		if !envName.MatchString(name) || !plainValue(env[name]) || isProxyVar(name) {
			return "", fmt.Errorf("synthetic env: name %q: %w", name, ErrSpec)
		}
		b.WriteString(name + "=" + env[name] + "\n")
	}
	dir := filepath.Join(s.work, "env-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	file := filepath.Join(dir, envFileName)
	// G306: the container user (65534) must read it; the work directory is
	// 0700, so no other host user can reach it, and it holds no secret.
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil { //nolint:gosec // G306, see above
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	return file, nil
}
