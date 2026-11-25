// Package releasescripts tests the release workflow's shell scripts that
// hold a secret, today .github/scripts/package-repos.sh (ADR 0033).
//
// That script is the only code that holds PACKAGE_REPOS_TOKEN, which can
// rewrite the Homebrew tap and the Scoop bucket every brew and scoop user
// installs from, so its refusals are protections: no token or a prerelease
// publishes nothing, a pin that checksums.txt does not list or a URL outside
// the tag's release stops it before any call, and it never moves the tap or
// bucket to an older version. The tests run it under bash with a fake gh on
// PATH against a small dist/ in t.TempDir(), so they need no network, token
// or release, and run in make check and the required protections job. They
// skip on Windows, where the release workflow does not run; CI runs them on
// Linux. The package has no product code and the layers table
// (internal/tools/*) keeps it out of the binary.
package releasescripts
