package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/recipe"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/verify"
)

// runRecipe dispatches the recipe commands. The authoring commands (ADR
// 0025) take one recipe file, named relative to the working directory;
// add (ADR 0028) takes a pinned source and the operator's clone of it.
// None reads a recipe from config; scan loads only what add installed.
func runRecipe(e env, args []string) int {
	if len(args) > 0 && args[0] == "add" {
		if len(args) != 3 {
			printError(e.stderr, "creep recipe add", errors.New("want github.com/<owner>/<repo>@<full commit SHA> and the directory of your clone at that commit"))
			return exitcode.ConfigError
		}
		return runRecipeAdd(e, args[1], args[2])
	}
	if len(args) != 2 {
		printError(e.stderr, "creep recipe", errors.New("want new, lint or test and one recipe file, or add github.com/<owner>/<repo>@<commit> <clone directory>"))
		return exitcode.ConfigError
	}
	switch args[0] {
	case "new":
		return runRecipeNew(e, args[1])
	case "lint":
		return runRecipeLint(e, args[1])
	case "test":
		return runRecipeTest(e, args[1])
	}
	printError(e.stderr, "creep recipe", fmt.Errorf("unknown subcommand %q: want new, lint, test or add", args[0]))
	return exitcode.ConfigError
}

// runRecipeNew writes the template recipe to a new file, never over an
// existing file or through a link.
func runRecipeNew(e env, name string) int {
	if err := writeNewRecipe(name); err != nil {
		printError(e.stderr, "creep recipe new", err)
		return exitcode.ConfigError
	}
	shown := escapeControl(name)
	fmt.Fprintf(e.stdout, "recipe: wrote %s; edit it, then run creep recipe lint %s and creep recipe test %s\n", shown, shown, shown)
	return exitcode.OK
}

// runRecipeLint checks a recipe with no model call: format, limits,
// fixtures' lines and the PoC template.
func runRecipeLint(e env, name string) int {
	r, _, err := lintRecipe(name)
	if err != nil {
		printError(e.stderr, "creep recipe lint", err)
		return exitcode.ConfigError
	}
	warnSplitClass(e.stderr, "recipe "+r.ID, r)
	fmt.Fprintf(e.stdout, "recipe %s: valid (%s); its fixtures are not checked yet: run creep recipe test %s\n", r.ID, r.Class, escapeControl(name))
	return exitcode.OK
}

// runRecipeTest loads a recipe: lint, then both fixtures through the
// reader with the configured model, at its calibrated tier. A refused
// recipe or a setup error exits 2; a model failure exits 3.
func runRecipeTest(e env, name string) int {
	_, data, err := lintRecipe(name)
	if err != nil {
		printError(e.stderr, "creep recipe test", err)
		return exitcode.ConfigError
	}
	ctx := context.Background()
	s, err := openRecipeSession(ctx, e)
	if err != nil {
		printError(e.stderr, "creep recipe test", err)
		return exitcode.ConfigError
	}
	defer s.close()
	r, tier, err := s.loadRecipe(ctx, e.stderr, data)
	s.finishRecipeRun(err)
	if err != nil {
		printError(e.stderr, "creep recipe test", err)
		return recipeFailureCode(err)
	}
	fmt.Fprintf(e.stdout, "recipe %s: loaded at tier %s: the vulnerable fixture was flagged and the safe fixture was clean\n", r.ID, tier)
	return exitcode.OK
}

// openRecipeSession opens a model session like scan's, from the operator's
// config, without opening the repository or touching the reports.
func openRecipeSession(ctx context.Context, e env) (*session, error) {
	resolved, err := loadConfig(e.opts)
	if err != nil {
		return nil, err
	}
	if err := checkModelConfig(resolved.Config.Model); err != nil {
		return nil, err
	}
	s := &session{cfg: resolved.Config, opts: e.opts, deps: e.deps, stats: newRunStats(e.deps.now)}
	if err := s.openRun(); err != nil {
		s.close()
		return nil, err
	}
	if err := s.connect(ctx, e, resolved); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// loadRecipe runs the tool canary and calibration as scan does, then
// recipe.Load at the calibrated tier.
func (s *session) loadRecipe(ctx context.Context, stderr io.Writer, data []byte) (*recipe.Recipe, reader.Tier, error) {
	warnPreset(stderr, s.cfg.Model)
	fmt.Fprintf(stderr, "recipe test: sends the recipe's hint and its two fixtures, redacted, to %s\n", escapeControl(wholeFileTarget(s.cfg.Model, s.link.command)))
	if err := s.checkTools(ctx); err != nil {
		return nil, "", fmt.Errorf("tool canary: %w", err)
	}
	cal, err := s.calibrate(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("calibration: %w", err)
	}
	tier, err := readerTier(cal.Tier)
	if err != nil {
		return nil, "", err
	}
	r, _, err := recipe.Checker{Model: s.model, Redactor: s.red, Tier: tier}.Load(ctx, data, checkRecipePoC)
	return r, tier, err
}

// finishRecipeRun writes the run's end line, so a recipe test never looks
// like an interrupted scan that creep resume could continue.
func (s *session) finishRecipeRun(err error) {
	outcome, reason := state.OutcomeComplete, ""
	if err != nil {
		outcome, reason = state.OutcomeIncomplete, "recipe_not_loaded"
	}
	_ = s.run.Finish(outcome, reason)
}

// recipeFailureCode is 2 for a refused recipe or an unmapped tier, and the
// model's code (3, or its own) for anything else, so a model failure never
// reads as a bad recipe, and neither ever exits 0.
func recipeFailureCode(err error) int {
	if errors.Is(err, recipe.ErrInvalid) || errors.Is(err, recipe.ErrFixtures) || errors.Is(err, errUnmapped) {
		return exitcode.ConfigError
	}
	return failureCode(err)
}

// lintRecipe reads and parses a recipe file.
func lintRecipe(name string) (*recipe.Recipe, []byte, error) {
	data, err := readRecipeFile(name)
	if err != nil {
		return nil, nil, err
	}
	r, err := recipe.Parse(data, checkRecipePoC)
	if err != nil {
		return nil, nil, fmt.Errorf("recipe %q: %w", name, err)
	}
	return r, data, nil
}

// checkRecipePoC holds a recipe's PoC to the rules a model's PoC meets
// (ADR 0019): a closed verify.Request, decoded strictly and validated, of
// a template whose oracle proves the recipe's class.
func checkRecipePoC(class string, raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req verify.Request
	if err := dec.Decode(&req); err != nil {
		return errors.New("not a PoC template with its parameters")
	}
	p, err := verify.Build(req)
	if err != nil {
		return err
	}
	if !verify.Fits(verifyClass(class), p) {
		return fmt.Errorf("template %s does not prove %s", p.Template(), class)
	}
	return nil
}

// verifyClass maps a recipe class to the class names verify's templates
// are listed under; a class with no template maps to itself and fits none.
func verifyClass(class string) string {
	if class == "sql_injection" {
		return "sqli"
	}
	return class
}

// readRecipeFile reads a recipe the operator named: a relative path
// (report.ValidPath) inside the working directory, with no link or special
// file at or above it, opened without blocking and capped. The open goes
// through the working directory's os.Root, so a directory swapped for a
// link after checkRecipePath cannot move the read out of the tree.
func readRecipeFile(name string) ([]byte, error) {
	if err := checkRecipePath(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, configError("recipe", name, err)
	}
	defer root.Close()
	return readCappedFile(recipeOpener(root), "recipe", filepath.FromSlash(name), recipe.MaxFileBytes)
}

// recipeOpener opens a recipe inside root and accepts it only if it is the
// regular, singly linked file root.Lstat saw: root follows a final link
// that stays in the tree, which a recipe path must not be.
func recipeOpener(root *os.Root) configOpener {
	return func(label, file string) (*os.File, os.FileInfo, error) {
		before, err := root.Lstat(file)
		if errors.Is(err, os.ErrNotExist) {
			// os.ErrNotExist, which recipestore.ReadFunc promises for an
			// absent file; its text matches errNoFile's.
			return nil, nil, fmt.Errorf("%s %q: %w", label, file, os.ErrNotExist)
		}
		if err != nil {
			return nil, nil, configError(label, file, err)
		}
		if !before.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("%s %q: must be a regular file, not a link or special file", label, file)
		}
		f, info, err := openRegularInRoot(root, file)
		if err != nil {
			return nil, nil, configError(label, file, err)
		}
		if !os.SameFile(before, info) || linkCount(info) > 1 {
			f.Close()
			return nil, nil, fmt.Errorf("%s %q: changed while being opened or a hard link", label, file)
		}
		return f, info, nil
	}
}

// checkRecipePath refuses a path outside report.ValidPath, one without
// .json, and one with a link, junction or special file in a directory
// above it, which could move the read or the write out of the tree.
func checkRecipePath(name string) error {
	if !report.ValidPath(name) || path.Ext(name) != ".json" || strings.ContainsRune(name, ':') {
		return fmt.Errorf("recipe %q: want a relative path to a .json file inside the working directory, with / separators and no . or .. segment", name)
	}
	for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
		info, err := os.Lstat(filepath.FromSlash(dir))
		if err != nil {
			return nil // a missing directory fails the open or write with its own error
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
			return fmt.Errorf("recipe %q: a directory above the file is a link or special file", name)
		}
	}
	return nil
}

// writeNewRecipe creates name with the template, exclusively, inside the
// working directory's os.Root: an existing file or a link there is never
// written, and a directory swapped for a link after checkRecipePath cannot
// move the write out of the tree.
func writeNewRecipe(name string) error {
	if err := checkRecipePath(name); err != nil {
		return err
	}
	root, err := os.OpenRoot(".")
	if err != nil {
		return configError("recipe", name, err)
	}
	defer root.Close()
	return createInRoot(root, name)
}

// createInRoot writes the template to name inside root, never over a file;
// a failed write removes what it created.
func createInRoot(root *os.Root, name string) error {
	file := filepath.FromSlash(name)
	f, err := root.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return configError("recipe", name, err)
	}
	_, err = f.Write(recipe.Template())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(file)
		return configError("recipe", name, err)
	}
	return nil
}
