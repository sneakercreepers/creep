package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// markerTable is the only kind of name DatabaseHasTable looks up: the
// table a PoC's SQL payload creates, named by creep with a fresh nonce.
var markerTable = regexp.MustCompile(`^creep_[a-z0-9]{16,48}$`)

// markerTimeout bounds the lookup.
const markerTimeout = time.Minute

// DatabaseHasTable reports whether the run's database holds the table, the
// side effect a PoC's SQL payload leaves when the injection works. It asks
// with a fixed query of creep's from a client container on the run
// network; the name is creep's own marker, never the model's text.
func (s *Sandbox) DatabaseHasTable(ctx context.Context, table string) (bool, error) {
	if !markerTable.MatchString(table) {
		return false, fmt.Errorf("database lookup: table name: %w", ErrSpec)
	}
	if err := s.abortErr(); err != nil {
		return false, err
	}
	db, ok := s.readyDatabase()
	if !ok {
		return false, fmt.Errorf("database lookup: no database: %w", ErrSpec)
	}
	res, err := s.start(ctx, markerSpec(db, table))
	if err != nil {
		return false, fmt.Errorf("database lookup: %w", err)
	}
	switch answer := string(bytes.TrimSpace(res.Output)); {
	case res.ExitCode != 0 || res.Truncated:
		return false, fmt.Errorf("database lookup (exit %d): %w", res.ExitCode, ErrDatabase)
	case answer == "t":
		return true, nil
	case answer == "f":
		return false, nil
	}
	return false, fmt.Errorf("database lookup: %w", ErrRunnerAnswer)
}

func (s *Sandbox) readyDatabase() (Database, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready == nil {
		return Database{}, false
	}
	return *s.ready, true
}

// markerSpec is psql on the run network with the synthetic password in
// its environment, never on its command line, and without reading a
// psqlrc (-X).
func markerSpec(db Database, table string) Spec {
	query := "SELECT to_regclass('public." + table + "') IS NOT NULL"
	return Spec{
		Image: DatabaseImage,
		Cmd: []string{"psql", "-X", "-q", "-t", "-A", "-h", db.Host, "-p", strconv.Itoa(db.Port),
			"-U", db.User, "-d", db.Name, "-c", query},
		Env:       map[string]string{"PGPASSWORD": db.Password},
		Timeout:   markerTimeout,
		networked: true, tmpfs: []string{pgData},
	}
}
