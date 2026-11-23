// Package recipe reads, checks and loads recipes: source, sink and hint
// records for one vulnerability class, with a vulnerable and a safe
// fixture, written as data by people outside the core (ADR 0025).
//
// It exists because a recipe is untrusted text that creep sends to a
// model, so everything that keeps a recipe from steering creep lives in one
// place:
//
//   - The format is a closed JSON schema (Recipe, published in
//     docs/schemas/recipe-v1.json, which only tests read). Parse decodes it
//     strictly: version 1, unknown fields, trailing data, repeated keys and
//     keys in another case are refused, and every field has a bound
//     (MaxFileBytes and the other limits). Errors name the field, never
//     quote a value.
//   - A recipe holds no endpoint, consent, gate, redaction rule, command or
//     path. Its class comes from the reader's closed set. Its PoC, if any,
//     is a verify.Request (ADR 0019): a closed template with bounded
//     parameters, checked by the caller's PoCCheck (recipe may not import
//     verify), which also refuses a template whose oracle cannot prove the
//     class.
//   - The hint is the only free text that leaves the package, and only
//     through reader.Target.Hint: the reader redacts and escapes it and
//     shows it as data in its HINT block, through the gateway. Nothing here
//     imports the planner, and a check returns only reader Signals, so no
//     recipe text can reach planner input (protect_test.go).
//   - Load is the only way to get a usable recipe: it runs both fixtures
//     through the reader and refuses the recipe (ErrFixtures) unless the
//     vulnerable fixture is flagged and the safe one is clean, each on a
//     whole slice.
//
// Recipes never come from the scanned repository: no config key names one,
// so creep.yaml cannot add or loosen any. `creep recipe lint` runs Parse,
// `creep recipe test` runs Load, and `creep recipe new` writes Template.
//
// Installed recipes (ADR 0028) are pinned, never fetched: ParseSource takes
// github.com/<owner>/<repo> at a full 40-hex commit only (no branch or
// tag); DetachedHead and OriginRepository check the operator's own clone;
// Lock (creep.lock) is a closed format whose Pin.Verify checks each
// installed file's SHA-256; Allowed applies the org policy's
// recipe_sources; HintFor picks the hint a hypothesis gets. The package
// does no file I/O: internal/cli reads the clone and the store.
package recipe
