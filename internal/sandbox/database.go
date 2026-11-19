package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DatabaseImage is PostgreSQL 17.12 on Alpine (the multi-arch index),
// pinned by digest. creep never pulls it; the operator does.
const DatabaseImage = "docker.io/library/postgres@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32"

// ErrDatabase marks a database that did not come up: a migration failed,
// or the server did not start in time.
var ErrDatabase = errors.New("sandbox database did not start")

// The database's fixed shape. Its data directory is the image's VOLUME,
// covered by a tmpfs, so the data lives in the container's memory only.
const (
	databaseAlias = "db"
	databasePort  = 5432
	databaseName  = "app"
	databaseUser  = "creep"
	pgData        = "/var/lib/postgresql/data"
	pgSocket      = "/var/run/postgresql"
	seedTarget    = "/docker-entrypoint-initdb.d/seed.sql"
	readyTimeout  = 2 * time.Minute
)

// Bounds on the migrations a database is seeded from.
const (
	maxMigrations    = 512
	maxMigrationSize = 1 << 20
	maxSeedSize      = 8 << 20
)

// Migration is one SQL migration of the scanned project, read by the
// caller (MigrationPaths picks and orders them).
type Migration struct {
	Path string
	SQL  []byte
}

// Database is where PoCs on the run's network reach the database. The
// password is a fresh random placeholder: nothing in it is real.
type Database struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
}

// URL is the database's connection URL for a PoC or the app.
func (d Database) URL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", d.User, d.Password, d.Host, d.Port, d.Name)
}

// StartDatabase starts the run's PostgreSQL on its internal network and
// seeds it with the migrations, in the order given, and nothing else: the
// seed is the only file mounted, the data directory is a tmpfs, and the
// credentials are random placeholders. The canary runs first, as before
// every batch. One database per run; Close removes it.
func (s *Sandbox) StartDatabase(ctx context.Context, migrations []Migration) (Database, error) {
	seed, err := s.writeSeed(migrations)
	if err != nil {
		return Database{}, err
	}
	if err := s.clearNetwork(ctx); err != nil {
		return Database{}, err
	}
	if err := s.claimDatabase(); err != nil {
		return Database{}, err
	}
	db := Database{Host: databaseAlias, Port: databasePort, Name: databaseName, User: databaseUser,
		Password: "creep-synthetic-" + rand.Text()}
	if _, err := s.start(ctx, databaseSpec(seed, db)); err != nil {
		return Database{}, fmt.Errorf("start database: %w", err)
	}
	if err := s.waitReady(ctx, db); err != nil {
		return Database{}, err
	}
	return db, nil
}

func (s *Sandbox) claimDatabase() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.database {
		return fmt.Errorf("the run already has a database: %w", ErrSpec)
	}
	s.database = true
	return nil
}

// databaseSpec is the database service: the image's own entry point runs
// the seed through psql with ON_ERROR_STOP, then serves on the network.
func databaseSpec(seed string, db Database) Spec {
	return Spec{
		Image: DatabaseImage,
		Env: map[string]string{
			"POSTGRES_USER": db.User, "POSTGRES_PASSWORD": db.Password, "POSTGRES_DB": db.Name,
			"PGDATA": pgData + "/pgdata", // a directory initdb creates, so user 65534 owns it
		},
		Mounts:    []Mount{{Source: seed, Target: seedTarget}},
		networked: true, alias: databaseAlias, detach: true,
		tmpfs: []string{pgData, pgSocket},
	}
}

// waitReady polls the server from a client container on the network. The
// image's entry point listens on the network only after the seed ran, so
// ready means seeded; a failed migration stops the server, and the poll
// runs out.
func (s *Sandbox) waitReady(ctx context.Context, db Database) error {
	poll := "end=$(($(date +%s)+90)); while [ $(date +%s) -lt $end ]; do " +
		"pg_isready -q -t 2 -h " + db.Host + " -p " + strconv.Itoa(db.Port) + " -U " + db.User + " -d " + db.Name +
		" && exit 0; sleep 1; done; exit 1"
	res, err := s.start(ctx, Spec{
		Image: DatabaseImage, Cmd: []string{"sh", "-c", poll}, Timeout: readyTimeout,
		networked: true, tmpfs: []string{pgData},
	})
	if err != nil {
		return fmt.Errorf("wait for database: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("database not ready (exit %d): %w", res.ExitCode, ErrDatabase)
	}
	return nil
}

// writeSeed writes the migrations, in order, as one SQL file in the work
// directory: the only data the database ever gets.
func (s *Sandbox) writeSeed(migrations []Migration) (string, error) {
	seed, err := seedSQL(migrations)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.work, "seed-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("database seed: %w", err)
	}
	path := filepath.Join(dir, "seed.sql")
	// G306: the container user must read it; the work directory is 0700.
	if err := os.WriteFile(path, seed, 0o644); err != nil { //nolint:gosec // G306, see above
		return "", fmt.Errorf("database seed: %w", err)
	}
	return path, nil
}

// seedSQL joins the migrations. A ";" line after each ends a last
// statement that lacks one; migration paths never enter the SQL.
func seedSQL(migrations []Migration) ([]byte, error) {
	if len(migrations) > maxMigrations {
		return nil, fmt.Errorf("database seed: %d migrations: %w", len(migrations), ErrSpec)
	}
	var b bytes.Buffer
	for i, m := range migrations {
		if len(m.SQL) > maxMigrationSize || bytes.IndexByte(m.SQL, 0) >= 0 {
			return nil, fmt.Errorf("database seed: migration %q: too large or binary: %w", m.Path, ErrSpec)
		}
		fmt.Fprintf(&b, "-- creep: migration %d of %d\n", i+1, len(migrations))
		b.Write(m.SQL)
		b.WriteString("\n;\n")
		if b.Len() > maxSeedSize {
			return nil, fmt.Errorf("database seed: over %d bytes: %w", maxSeedSize, ErrSpec)
		}
	}
	return b.Bytes(), nil
}
