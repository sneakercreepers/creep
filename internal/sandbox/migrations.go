package sandbox

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// migrationDirs are the root directories plain SQL migrations live in
// (golang-migrate, Flyway, dbmate without markers, Supabase), checked in
// this order; the first that holds one is the project's.
var migrationDirs = []string{"migrations", "db/migrations", "database/migrations", "sql/migrations", "supabase/migrations"}

// prismaDir holds one directory per migration with a migration.sql in it.
const prismaDir = "prisma/migrations"

// MigrationPaths picks the project's SQL migrations from a list of
// repository paths (slash-separated, relative) and returns them in the
// order they apply: digit runs compare as numbers, so 2_x runs before
// 10_x. Down migrations (*.down.sql, *_down.sql) are left out. One set
// only: the first directory of migrationDirs that has any, else Prisma's.
func MigrationPaths(paths []string) ([]string, error) {
	for _, dir := range migrationDirs {
		if found := sqlIn(paths, dir); len(found) > 0 {
			return ordered(found)
		}
	}
	var prisma []string
	for _, p := range paths {
		parent, name := path.Split(p)
		if name == "migration.sql" && path.Dir(strings.TrimSuffix(parent, "/")) == prismaDir {
			prisma = append(prisma, p)
		}
	}
	return ordered(prisma)
}

// sqlIn returns the up-migration .sql files directly in dir.
func sqlIn(paths []string, dir string) []string {
	var found []string
	for _, p := range paths {
		parent, name := path.Split(p)
		lower := strings.ToLower(name)
		if parent != dir+"/" || !strings.HasSuffix(lower, ".sql") ||
			strings.HasSuffix(lower, ".down.sql") || strings.HasSuffix(lower, "_down.sql") {
			continue
		}
		found = append(found, p)
	}
	return found
}

func ordered(found []string) ([]string, error) {
	if len(found) > maxMigrations {
		return nil, fmt.Errorf("%d migrations, at most %d: %w", len(found), maxMigrations, ErrSpec)
	}
	slices.SortFunc(found, naturalCompare)
	return slices.Compact(found), nil
}

// naturalCompare orders strings with digit runs compared as numbers.
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		ra, restA := leadingRun(a)
		rb, restB := leadingRun(b)
		if c := compareRun(ra, rb); c != 0 {
			return c
		}
		a, b = restA, restB
	}
	return len(a) - len(b)
}

// leadingRun splits s after its first run of digits or of non-digits.
func leadingRun(s string) (string, string) {
	digit := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == digit {
		i++
	}
	return s[:i], s[i:]
}

func compareRun(a, b string) int {
	if !isDigit(a[0]) || !isDigit(b[0]) {
		return strings.Compare(a, b)
	}
	ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(ta) != len(tb) {
		return len(ta) - len(tb)
	}
	if c := strings.Compare(ta, tb); c != 0 {
		return c
	}
	return len(a) - len(b) // equal numbers: the shorter spelling first
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
