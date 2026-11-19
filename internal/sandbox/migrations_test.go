package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestMigrationPaths(t *testing.T) {
	tests := map[string]struct {
		paths []string
		want  []string
	}{
		"numeric order": {
			[]string{"migrations/10_c.sql", "migrations/2_b.sql", "migrations/1_a.sql"},
			[]string{"migrations/1_a.sql", "migrations/2_b.sql", "migrations/10_c.sql"},
		},
		"golang-migrate up only": {
			[]string{"migrations/1_a.up.sql", "migrations/1_a.down.sql", "migrations/2_b_down.sql", "migrations/2_b.up.sql"},
			[]string{"migrations/1_a.up.sql", "migrations/2_b.up.sql"},
		},
		"flyway": {
			[]string{"db/migrations/V10__x.sql", "db/migrations/V9__y.sql"},
			[]string{"db/migrations/V9__y.sql", "db/migrations/V10__x.sql"},
		},
		"first directory wins": {
			[]string{"db/migrations/1.sql", "migrations/1.sql"},
			[]string{"migrations/1.sql"},
		},
		"only direct children": {
			[]string{"migrations/old/1.sql", "migrations/README.md", "app/migrations/1.sql", "migrations.sql"},
			nil,
		},
		"upper-case extension": {[]string{"migrations/1.SQL"}, []string{"migrations/1.SQL"}},
		"prisma": {
			[]string{"prisma/migrations/20240102_b/migration.sql", "prisma/migrations/20240101_a/migration.sql",
				"prisma/migrations/migration_lock.toml", "prisma/migrations/x/y/migration.sql"},
			[]string{"prisma/migrations/20240101_a/migration.sql", "prisma/migrations/20240102_b/migration.sql"},
		},
		"none": {[]string{"app.py", "schema.sql"}, nil},
		// Only clean paths inside the repository count, each once.
		"prisma dot-dot": {[]string{"prisma/migrations/../migration.sql"}, nil},
		"prisma behind a detour": {
			[]string{"a/../prisma/migrations/x/migration.sql", "prisma/migrations/x/../a/migration.sql", "prisma/migrations/a/migration.sql"},
			[]string{"prisma/migrations/a/migration.sql"},
		},
		"dot-dot in a flat dir": {[]string{"migrations/../1.sql", "x/../migrations/2.sql"}, nil},
		"absolute":              {[]string{"/migrations/1.sql", "/etc/migrations/1.sql"}, nil},
		"dot and empty elements": {
			[]string{"./migrations/1.sql", "migrations/./2.sql", "migrations//3.sql", "migrations/4.sql/"},
			nil,
		},
		"backslash":  {[]string{`migrations\1.sql`, `migrations/..\..\1.sql`}, nil},
		"duplicates": {[]string{"migrations/1.sql", "migrations/1.sql"}, []string{"migrations/1.sql"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := MigrationPaths(tt.paths)
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("MigrationPaths = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	var many []string
	for i := range maxMigrations + 1 {
		many = append(many, fmt.Sprintf("migrations/%d.sql", i))
	}
	if _, err := MigrationPaths(many); !errors.Is(err, ErrSpec) {
		t.Errorf("too many migrations: %v", err)
	}
}

func TestNaturalCompare(t *testing.T) {
	ordered := []string{"", "1", "01", "2", "10", "a", "a1", "a2", "a10", "b"}
	for i, a := range ordered {
		for j, b := range ordered {
			got := naturalCompare(a, b)
			if (i < j && got >= 0) || (i > j && got <= 0) || (i == j && got != 0) {
				t.Errorf("naturalCompare(%q, %q) = %d", a, b, got)
			}
		}
	}
}
