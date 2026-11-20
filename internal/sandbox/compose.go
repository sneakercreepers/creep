package sandbox

import (
	"strings"

	"go.yaml.in/yaml/v3"
)

// creep never runs `docker compose`: the compose file is hostile input
// (privileged services, host networks, host volumes, devices, extra hosts,
// build secrets, remote contexts, includes, variables read from the host).
// It is read only for where the one buildable service's Dockerfile is.
// Everything about how a service runs (ports, volumes, privileges,
// networks, environment) is never passed on: the app runs with creep's
// hardened profile, so those keys are neutralized by not existing.

// composeBuildKeys are the build keys creep uses (context, dockerfile,
// target) or may drop because they change nothing the sandbox relies on.
// Any other key (args, secrets, ssh, network, extra_hosts,
// additional_contexts, cache_from, privileged, entitlements,
// dockerfile_inline, platforms, ...) refuses the file.
var composeBuildKeys = map[string]bool{
	"context": true, "dockerfile": true, "target": true,
	"labels": true, "tags": true, "no_cache": true, "pull": true,
}

// knownComposeBuildKeys name a refused key in the detail; any other key is
// reported as unknown, so no repository text reaches the report.
var knownComposeBuildKeys = []string{
	"args", "secrets", "ssh", "network", "extra_hosts", "additional_contexts",
	"cache_from", "cache_to", "privileged", "entitlements", "dockerfile_inline",
	"platforms", "shm_size", "isolation", "ulimits",
}

// composeBuild finds the one service with a build section. found is false
// when no service builds.
func composeBuild(data []byte) (buildPlan, bool, *refusal) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return buildPlan{}, false, refuse(BuildComposeRefused, "parse")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return buildPlan{}, false, refuse(BuildComposeRefused, "parse")
	}
	if _, ok := lookup(root, "include"); ok {
		return buildPlan{}, false, refuse(BuildComposeRefused, "include")
	}
	services, ok := lookup(root, "services")
	switch {
	case hasMergeKey(root) || ok && hasMergeKey(services):
		return buildPlan{}, false, refuse(BuildComposeRefused, "merge_key")
	case !ok:
		return buildPlan{}, false, nil
	case services.Kind != yaml.MappingNode:
		return buildPlan{}, false, refuse(BuildComposeRefused, "services")
	}
	return serviceBuild(services)
}

func serviceBuild(services *yaml.Node) (buildPlan, bool, *refusal) {
	var build *yaml.Node
	for i := 1; i < len(services.Content); i += 2 {
		svc := resolveAlias(services.Content[i])
		b, ok := lookup(svc, "build")
		if !ok {
			continue
		}
		if build != nil {
			return buildPlan{}, false, refuse(BuildComposeRefused, "several_builds")
		}
		if _, ext := lookup(svc, "extends"); ext {
			return buildPlan{}, false, refuse(BuildComposeRefused, "extends")
		}
		if hasMergeKey(svc) {
			return buildPlan{}, false, refuse(BuildComposeRefused, "merge_key")
		}
		build = b
	}
	if build == nil {
		return buildPlan{}, false, nil
	}
	plan, why := buildSection(build)
	return plan, why == nil, why
}

// buildSection reads `build: <context>` or a mapping of allowed keys.
func buildSection(b *yaml.Node) (buildPlan, *refusal) {
	if b.Kind == yaml.ScalarNode {
		ctx, why := composePath(".", b, "build.context")
		return buildPlan{context: ctx, dockerfile: joinRepo(ctx, "Dockerfile")}, why
	}
	if b.Kind != yaml.MappingNode || hasMergeKey(b) {
		return buildPlan{}, refuse(BuildComposeRefused, "build")
	}
	for i := 0; i < len(b.Content); i += 2 {
		if key := keyText(b.Content[i]); !composeBuildKeys[key] {
			return buildPlan{}, refuse(BuildComposeRefused, refusedKey(key))
		}
	}
	plan := buildPlan{context: ".", dockerfile: "Dockerfile"}
	var why *refusal
	if n, ok := lookup(b, "context"); ok {
		if plan.context, why = composePath(".", n, "build.context"); why != nil {
			return buildPlan{}, why
		}
	}
	plan.dockerfile = joinRepo(plan.context, "Dockerfile")
	if n, ok := lookup(b, "dockerfile"); ok {
		if plan.dockerfile, why = composePath(plan.context, n, "build.dockerfile"); why != nil {
			return buildPlan{}, why
		}
	}
	if n, ok := lookup(b, "target"); ok {
		if !plainString(n) || !stageName.MatchString(n.Value) {
			return buildPlan{}, refuse(BuildComposeRefused, "build.target")
		}
		plan.target = n.Value
	}
	return plan, nil
}

func refusedKey(key string) string {
	for _, k := range knownComposeBuildKeys {
		if k == key {
			return "build." + k
		}
	}
	return "build.unknown_key"
}

// composePath is a string value naming a path inside base.
func composePath(base string, n *yaml.Node, key string) (string, *refusal) {
	if !plainString(n) {
		return "", refuse(BuildComposeRefused, key)
	}
	p, err := within(base, strings.TrimPrefix(n.Value, "./"))
	if err != nil {
		return "", refuse(BuildComposeRefused, key)
	}
	return p, nil
}

func joinRepo(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// plainString is a scalar string: no other YAML type or custom tag.
func plainString(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!str"
}

// lookup finds key in a mapping, following an alias for the value.
func lookup(m *yaml.Node, key string) (*yaml.Node, bool) {
	m = resolveAlias(m)
	if m.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if keyText(m.Content[i]) == key {
			return resolveAlias(m.Content[i+1]), true
		}
	}
	return nil, false
}

// hasMergeKey refuses YAML merge keys: what they pull in is easy to miss.
func hasMergeKey(m *yaml.Node) bool {
	m = resolveAlias(m)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := resolveAlias(m.Content[i]); k.ShortTag() == "!!merge" || k.Value == "<<" {
			return true
		}
	}
	return false
}

// keyText is a mapping key as Compose reads it: an alias key (*a: ...)
// stands for its anchor's text, so `*a` can spell "extends" or "context".
func keyText(n *yaml.Node) string {
	return resolveAlias(n).Value
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}
