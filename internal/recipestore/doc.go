// Package recipestore keeps installed recipes on disk: it reads the
// operator's clone of a recipe source, writes the files and creep.lock into
// ~/.creep/recipes, and verifies every pinned file before a scan uses it
// (ADR 0028).
//
// internal/recipe owns the formats (source, lock, recipe) and does no file
// I/O; internal/cli owns the commands. This package sits between them so
// the store layout, the clone checks, the exclusive writes and the
// removal of old commits live in one place, not in command wiring (v0.3
// architecture review A5). Every path stays inside an os.Root; the caller
// supplies the confined, capped, non-blocking read (Store.Read) and the
// PoC rule (Store.PoC), so the package opens no file it could block on and
// imports neither verify nor config.
package recipestore
