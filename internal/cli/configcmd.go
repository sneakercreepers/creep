package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"text/tabwriter"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// Default file locations. The user file is shown as "~/..." so messages and
// `config explain` output do not depend on the home directory.
const (
	policyEnv   = "CREEP_POLICY"
	userConfig  = ".creep/config.yaml"
	projectFile = "creep.yaml"
)

func runConfig(e env, args []string) int {
	if len(args) == 0 {
		printError(e.stderr, "creep config", errors.New("missing subcommand: want explain"))
		return exitcode.ConfigError
	}
	if args[0] != "explain" {
		printError(e.stderr, "creep config", fmt.Errorf("unknown subcommand %q: want explain", args[0]))
		return exitcode.ConfigError
	}
	if len(args) > 1 {
		printError(e.stderr, "creep config explain", fmt.Errorf("unexpected arguments: %q", args[1:]))
		return exitcode.ConfigError
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		printError(e.stderr, "creep config explain", err)
		return exitcode.ConfigError
	}
	mode, err := chooseMode(e)
	if err != nil {
		printError(e.stderr, "creep config explain", err)
		return exitcode.ConfigError
	}
	entries := slices.Concat(resolved.Explain(), resolved.ExplainMode(mode))
	if err := printExplain(e.stdout, resolved.Config.Output.Format, entries); err != nil {
		printError(e.stderr, "creep config explain", err)
		return exitcode.ConfigError
	}
	return exitcode.OK
}

// loadConfig reads every layer and resolves them. --config replaces the user
// and project files (see internal/config); the policy always applies.
func loadConfig(opts globalOptions) (*config.Resolved, error) {
	in := config.Inputs{Flags: configFlags(opts)}
	var err error
	if path := os.Getenv(policyEnv); path != "" {
		if err := requireAbsPolicy(path); err != nil {
			return nil, err
		}
		if in.Policy, err = readLayer(policyEnv, path, path); err != nil {
			return nil, err
		}
	}
	if opts.configPath != "" {
		in.Explicit, err = readLayer("--config", opts.configPath, opts.configPath)
		if err != nil {
			return nil, err
		}
		return resolve(in)
	}
	if in.User, err = readUserLayer(); err != nil {
		return nil, err
	}
	if in.Project, err = readProjectLayer(); err != nil {
		return nil, err
	}
	return resolve(in)
}

// resolve resolves the layers and checks the policy's consent entries
// with the gateway's own parser, and its recipe_sources with recipe's, so
// a bad entry is a configuration error
// (exit 2) for every command, before any run starts (#116).
func resolve(in config.Inputs) (*config.Resolved, error) {
	r, err := config.Load(in)
	if err != nil {
		return nil, err
	}
	if err := gateway.CheckPolicyConsent(r.PolicyConsent()); err != nil {
		return nil, fmt.Errorf("%s: %w", policyEnv, err)
	}
	sources, _ := r.PolicyRecipeSources()
	if err := recipe.CheckAllowlist(sources); err != nil {
		return nil, fmt.Errorf("%s: %w", policyEnv, err)
	}
	return r, nil
}

// readLayer reads a required file; name is how the layer is shown.
func readLayer(label, path, name string) (*config.File, error) {
	data, err := readConfigFile(label, path)
	if err != nil {
		return nil, err
	}
	return &config.File{Name: name, Data: data}, nil
}

// readOptional reads a file that may be absent.
func readOptional(label, path, name string) (*config.File, error) {
	f, err := readLayer(label, path, name)
	if errors.Is(err, errNoFile) {
		return nil, nil
	}
	return f, err
}

// readUserLayer skips the user file when there is no home directory, as in
// some CI containers.
func readUserLayer() (*config.File, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	return readOptional("user config", filepath.Join(home, filepath.FromSlash(userConfig)), "~/"+userConfig)
}

// requireAbsPolicy rejects a relative CREEP_POLICY: it would resolve against
// the working directory, which in CI is the scanned repository, so the
// repository could supply the policy meant to constrain it.
func requireAbsPolicy(path string) error {
	if filepath.IsAbs(path) {
		return nil
	}
	return fmt.Errorf("%s %q: must be an absolute path; a relative path resolves inside the scanned repository", policyEnv, path)
}

func readProjectLayer() (*config.File, error) {
	data, err := readConfigWith(openProjectConfig, "project config", projectFile)
	if errors.Is(err, errNoFile) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &config.File{Name: projectFile, Data: data}, nil
}

// printExplain prints every key, then the scan's mode and the gate it
// reads (#28).
func printExplain(w io.Writer, format string, entries []config.Entry) error {
	switch format {
	case "text":
		return printExplainText(w, entries)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	default:
		return fmt.Errorf("output format %q is not supported here: want text or json", format)
	}
}

// printExplainText escapes every cell: values and file names come from
// files the user may not have written (a cloned repository's creep.yaml).
func printExplainText(w io.Writer, entries []config.Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tVALUE\tSOURCE")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", escapeControl(e.Key), escapeControl(config.FormatValue(e.Value)), escapeControl(e.Source))
	}
	return tw.Flush()
}
