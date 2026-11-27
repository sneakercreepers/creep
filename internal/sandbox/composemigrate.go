package sandbox

import "go.yaml.in/yaml/v3"

// migrateService is the compose service whose command sets up the app's
// schema: the app's own migrate step, whatever its language or framework
// (#364). creep reads only that command from it and runs it in the image
// Build made (Migrate); the service's build, image, environment, volumes
// and every other key are never passed on, as for the app's service. An
// app without one sets up its own schema when it starts, or has none.
const migrateService = "migrate"

// composeMigrate reads the migrate service's command: a list of plain,
// non-empty strings within the profile's bounds. The string form is
// refused, since Compose splits it with shell rules creep would have to
// copy exactly; an entrypoint is refused, since creep would drop it and
// run something else than the file says.
func composeMigrate(services *yaml.Node) ([]string, *refusal) {
	svc, ok := lookup(services, migrateService)
	if !ok {
		return nil, nil
	}
	switch _, ext := lookup(svc, "extends"); {
	case svc.Kind != yaml.MappingNode:
		return nil, refuse(BuildComposeRefused, "migrate")
	case ext:
		return nil, refuse(BuildComposeRefused, "extends")
	case hasMergeKey(svc):
		return nil, refuse(BuildComposeRefused, "merge_key")
	}
	if _, ok := lookup(svc, "entrypoint"); ok {
		return nil, refuse(BuildComposeRefused, "migrate.entrypoint")
	}
	cmd, ok := lookup(svc, "command")
	if !ok {
		return nil, refuse(BuildComposeRefused, "migrate.command")
	}
	return migrateCommand(cmd)
}

func migrateCommand(n *yaml.Node) ([]string, *refusal) {
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
