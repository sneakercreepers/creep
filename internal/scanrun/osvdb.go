package scanrun

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// lockfileEcosystems maps each ecosystem's offline database
// (<db>/osv-scanner/<ecosystem>/all.zip) to the lockfile and manifest
// names, lowercased, that osv-scanner v2 matches against it. A name
// here that osv-scanner does not read only asks for one database too many,
// the strict side; a format missing here is the residual (ADR 0013).
var lockfileEcosystems = map[string][]string{
	"npm":         {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"},
	"PyPI":        {"pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock", "pylock.toml"},
	"Go":          {"go.mod"},
	"crates.io":   {"cargo.lock"},
	"RubyGems":    {"gemfile.lock", "gems.locked"},
	"Packagist":   {"composer.lock"},
	"Maven":       {"pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile", "verification-metadata.xml"},
	"NuGet":       {"packages.lock.json", "packages.config"},
	"Pub":         {"pubspec.lock"},
	"Hex":         {"mix.lock"},
	"CRAN":        {"renv.lock"},
	"ConanCenter": {"conan.lock"},
	"SwiftURL":    {"package.resolved"},
	"Hackage":     {"cabal.project.freeze", "stack.yaml.lock"},
}

// lockfileEcosystem is the ecosystem of a file named name, or "". Python
// requirements files and .NET deps files are matched by shape, as
// osv-scanner does.
func lockfileEcosystem(name string) string {
	lower := strings.ToLower(name)
	for eco, names := range lockfileEcosystems {
		if slices.Contains(names, lower) {
			return eco
		}
	}
	switch {
	case strings.HasSuffix(lower, ".txt") && strings.Contains(lower, "requirements"):
		return "PyPI"
	case strings.HasSuffix(lower, ".deps.json"):
		return "NuGet"
	}
	return ""
}

// osvPlan runs osv-scanner once over the repository, and not at all when
// the database lacks the ecosystem of a lockfile in it: osv-scanner logs
// the miss and reports no advisories for that file, which would read as
// evaluated (#226). The walk follows no link and skips .git; past the
// timeout it fails like the run would.
func osvPlan(ctx context.Context, job Job) (runPlan, Failure) {
	ecosystems, failure := repoEcosystems(ctx, job.Repo)
	if failure != FailNone {
		return runPlan{}, failure
	}
	for eco := range ecosystems {
		if !hasEcosystemDB(job.OSVDB, eco) {
			return runPlan{}, FailEcosystemDB
		}
	}
	return runPlan{sources: []string{job.Repo}}, FailNone
}

// repoEcosystems names the ecosystem of every regular lockfile under repo.
func repoEcosystems(ctx context.Context, repo string) (map[string]bool, Failure) {
	found := map[string]bool{}
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case ctx.Err() != nil:
			return ctx.Err()
		case d.IsDir() && d.Name() == ".git" && path != repo:
			return fs.SkipDir
		case d.Type().IsRegular() && lockfileEcosystem(d.Name()) != "":
			found[lockfileEcosystem(d.Name())] = true
		}
		return nil
	})
	switch {
	case ctx.Err() != nil:
		return nil, FailTimeout
	case err != nil:
		return nil, FailStart
	}
	return found, FailNone
}

// usableOSVDB reports a local database osv-scanner can match against:
// <db>/osv-scanner/<ecosystem>/all.zip, a non-empty regular file, for at
// least one ecosystem. With none, osv-scanner logs the miss and reports no
// advisories, which would read as evaluated.
func usableOSVDB(db string) bool {
	if db == "" || !filepath.IsAbs(db) {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(db, "osv-scanner"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if hasEcosystemDB(db, e.Name()) {
			return true
		}
	}
	return false
}

// hasEcosystemDB reports a non-empty regular all.zip for eco in db.
func hasEcosystemDB(db, eco string) bool {
	info, err := os.Stat(filepath.Join(db, "osv-scanner", eco, "all.zip"))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}
