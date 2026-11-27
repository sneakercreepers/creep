package sandbox

import "go.yaml.in/yaml/v3"

// migrateService is the compose service whose command sets up the app's
// schema: the app's own migrate step, whatever its language or framework
// (#364). creep reads only that command from it and runs it in the image
// Build made (Migrate); the service's build, image, environment, volumes
// and every other key are never passed on, as for the app's service. An
// app without one sets up its own schema when it starts, or has none.
const migrateService = "migrate"

// MigrateSkip is why a compose file's migrate service gives no migrate
// step while the app is still built: a form creep does not run exactly as
// Compose would. The app then sets up its own schema, or has none.
type MigrateSkip string

const (
	// MigrateSkipStringCommand: Compose splits a string command with shell
	// rules creep would have to copy exactly.
	MigrateSkipStringCommand MigrateSkip = "string_command"
	// MigrateSkipEntrypoint: creep would drop the entrypoint and run
	// something else than the file says.
	MigrateSkipEntrypoint MigrateSkip = "entrypoint"
	// MigrateSkipExtends: the service's settings come from another file.
	MigrateSkipExtends MigrateSkip = "extends"
	// MigrateSkipNoCommand: the image's own command would start the app.
	MigrateSkipNoCommand MigrateSkip = "no_command"
)

// MigrateSkips is the closed set of skip reasons.
func MigrateSkips() []MigrateSkip {
	return []MigrateSkip{MigrateSkipStringCommand, MigrateSkipEntrypoint, MigrateSkipExtends, MigrateSkipNoCommand}
}

// composeMigrate reads the migrate service's command: a list of plain,
// non-empty strings within the profile's bounds. A string command, an
// entrypoint, extends or no command skip the step with a closed reason;
// a malformed list or a merge key refuses the compose file, since creep
// cannot read it exactly.
func composeMigrate(services *yaml.Node) ([]string, MigrateSkip, *refusal) {
	svc, ok := lookup(services, migrateService)
	if !ok {
		return nil, "", nil
	}
	switch {
	case svc.Kind != yaml.MappingNode:
		return nil, "", refuse(BuildComposeRefused, "migrate")
	case hasMergeKey(svc):
		return nil, "", refuse(BuildComposeRefused, "merge_key")
	}
	if skip := migrateSkip(svc); skip != "" {
		return nil, skip, nil
	}
	cmd, _ := lookup(svc, "command")
	argv, why := migrateCommand(cmd)
	return argv, "", why
}

// migrateSkip names a migrate service form creep does not run.
func migrateSkip(svc *yaml.Node) MigrateSkip {
	cmd, hasCmd := lookup(svc, "command")
	if _, ok := lookup(svc, "extends"); ok {
		return MigrateSkipExtends
	}
	if _, ok := lookup(svc, "entrypoint"); ok {
		return MigrateSkipEntrypoint
	}
	switch {
	case !hasCmd:
		return MigrateSkipNoCommand
	case resolveAlias(cmd).Kind == yaml.ScalarNode:
		return MigrateSkipStringCommand
	}
	return ""
}

func migrateCommand(n *yaml.Node) ([]string, *refusal) {
	n = resolveAlias(n)
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 || len(n.Content) > maxArgs {
		return nil, refuse(BuildComposeRefused, "migrate.command")
	}
	argv := make([]string, 0, len(n.Content))
	for _, arg := range n.Content {
		arg = resolveAlias(arg)
		if !plainString(arg) || arg.Value == "" || !plainValue(arg.Value) {
			return nil, refuse(BuildComposeRefused, "migrate.command")
		}
		argv = append(argv, arg.Value)
	}
	return argv, nil
}
