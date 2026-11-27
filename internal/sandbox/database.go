package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// DatabaseImage is PostgreSQL 17.12 on Alpine (the multi-arch index),
// pinned by digest. creep never pulls it; the operator does.
const DatabaseImage = "docker.io/library/postgres@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32"

// ErrDatabase marks a database that did not come up in time.
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
	readyTimeout  = 2 * time.Minute
)

// Database is where PoCs and the app on the run's network reach the
// database. The password is a fresh random placeholder: nothing in it is
// real.
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

// StartDatabase starts the run's PostgreSQL, empty, on its internal
// network: nothing is mounted, the data directory is a tmpfs, and the
// credentials are random placeholders. The app's own migrate step
// (Migrate), or the app itself when it starts, sets up its schema; creep
// never reads SQL from the repository. The canary runs first, as before
// every batch. One database per run; Close removes it.
func (s *Sandbox) StartDatabase(ctx context.Context) (Database, error) {
	if err := s.clearNetwork(ctx); err != nil {
		return Database{}, err
	}
	if err := s.claimDatabase(); err != nil {
		return Database{}, err
	}
	db := Database{Host: databaseAlias, Port: databasePort, Name: databaseName, User: databaseUser,
		Password: "creep-synthetic-" + rand.Text()}
	if _, err := s.start(ctx, databaseSpec(db)); err != nil {
		return Database{}, fmt.Errorf("start database: %w", err)
	}
	if err := s.waitReady(ctx, db); err != nil {
		return Database{}, err
	}
	s.mu.Lock()
	s.ready = &db
	s.mu.Unlock()
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

// databaseSpec is the database service: the image's own entry point
// creates the empty database, then serves on the network.
func databaseSpec(db Database) Spec {
	return Spec{
		Image: DatabaseImage,
		Env: map[string]string{
			"POSTGRES_USER": db.User, "POSTGRES_PASSWORD": db.Password, "POSTGRES_DB": db.Name,
			"PGDATA": pgData + "/pgdata", // a directory initdb creates, so user 65534 owns it
		},
		networked: true, alias: databaseAlias, detach: true,
		tmpfs: []string{pgData, pgSocket},
	}
}

// waitReady polls the server from a client container on the network. The
// image's entry point listens on the network only after initdb, so ready
// means the empty database exists.
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
