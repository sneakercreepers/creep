// Package calibrate measures the user's model per vulnerability class.
//
// It exists because public benchmarks are in every model's training data, so
// a score on them says little about the model in front of us. Calibration
// tasks are generated instead: Generate turns a seed into TaskCount tasks by
// mutating vulnerability templates.
//
//   - Templates are data, not code (docs/architecture.md §5, §8): each one is
//     a directory under templates/ holding template.json (class, language,
//     identifier pools, sink lines and markers) and a vulnerable.tmpl and
//     safe.tmpl twin. Adding a template adds a directory, not Go code.
//   - A mutation only renames identifiers, drawn from the template's own
//     pools, and inserts neutral constant lines before the sink. Loading
//     refuses a pool value that is not a plain identifier, is a keyword,
//     repeats in another pool or already appears in the template, so a
//     rename can never alias a name the code uses. The ground truth (class,
//     vulnerable or safe, sink line) is therefore fixed by the template, and
//     the twin markers in template.json let tests check every task for it.
//   - The generator is pure: seed in, tasks out, no I/O beyond the embedded
//     files. It reads randomness only from a PCG source seeded with the seed
//     and draws through intN, so the tasks depend on the PCG algorithm and
//     this package alone, not on math/rand helpers that may change between
//     Go releases. Golden hashes in the tests pin the output; changing a
//     template changes them, which is intended: it changes calibration
//     results, and the PR needs the affects-results label.
//   - Half the tasks are vulnerable and half are their safe twins, spread
//     round-robin over every template, then shuffled so position says
//     nothing about the label.
//   - A safe twin has no defensible finding in any class, not only its
//     template's: scoring counts any finding on it as a false positive, so
//     a twin a precise model could rightly flag under another class would
//     penalize the best models (#162). Caller input reaches a sink only in
//     a form the sink cannot misread: an allowlisted value, the value that
//     was checked, a bound scalar parameter or a path confined to a root;
//     a twin that reads per-owner rows scopes them to the logged-in owner,
//     and a merge writes only into own, prototype-free objects.
//
// Templates hold no real secret or hostname; hosts use the reserved
// .invalid top-level domain.
//
// Run scores a model on those tasks (run.go, score.go, tier.go):
//   - Every call is a models.Complete through the caller's *models.HTTP, so
//     consent, budget and egress.log apply; every prompt is first passed
//     whole through the run's redact.File, like a repository file, and its
//     marker counts go to egress.log. Only the numbered code reaches the
//     model, never a task's template, ID, class or label.
//   - Calls are made one at a time in a fixed order (tasks, then tool
//     probes, then context probes), so a recorded run replays exactly.
//   - Scoring: a safe twin is right only when called safe; a vulnerable
//     task needs its class and a line within 2 of the sink (the source line
//     may sit just above it). A reply that stays invalid after retries is
//     wrong and counts against the structured-output check. Any other
//     failure ends the run with no Result.
//   - Each class gets a 95% Wilson interval. Tiers use the interval's lower
//     bound, never the point score, because classes have as few as 8 tasks;
//     the comparison is exact rational arithmetic, so the tier of a recorded
//     run is the same on every platform. A class with no tasks is
//     unmeasured and keeps the model at tier S.
//   - Probes, seeded on their own PCG stream: tool calling (pick the right
//     tool, copy the argument exactly) and effective context (find one
//     assignment in 8, 32, then 128 KiB of similar ones, stopping at the
//     first miss). A probe refused for its size (HTTP 400 or 413, or the
//     token budget) is a miss, not a failed run. ContextCheck records the
//     size that missed and why (wrong answer, invalid output, the status,
//     the budget), and Header shows it: a 400 for another reason, such as
//     a bad parameter, holds the model at tier S, and the report says so.
//   - The Result records the seed, a hash of the task set and
//     PromptVersion, so a cached result is tied to what it measured.
//
// RunCached (cache.go) keeps one result per model for MaxAge (30 days by
// default, calibration.cache_days) in a state.Store, normally the user's
// cache directory:
//   - The key is the SHA-256 of the model's identity (contract, endpoint
//     URL, model name), the client settings that change its answers
//     (models.Settings: structured output, max output tokens, retries), the
//     seed, the task-set hash and PromptVersion. The model name is the
//     model's version as far as creep can tell: a dated name gets its own
//     entry; an alias such as "-latest" that moves to a new snapshot is
//     measured again only after MaxAge, or with --recalibrate. A new creep
//     whose templates, prompts or key fields changed never reuses a tier:
//     entries under older keys are never looked up again.
//   - A cached result is used only when its age is in [0, MaxAge), its line
//     is authenticated by internal/state, it decodes strictly, it matches
//     the key, its context check is one a run can produce, and the current
//     rules give it the tier it records. A torn, planted, linked or
//     inconsistent file is recalibrated over, never read. This holds for
//     files: a calibrations/ directory that is a link, junction or file
//     fails closed before any model call, with or without --recalibrate,
//     and the error names the directory to remove. A file from a newer
//     creep fails closed (state.ErrUnsupportedVersion) unless Recalibrate
//     (--recalibrate) replaces it.
//   - The clock is injected (CacheOptions.Now), so expiry is tested at its
//     boundaries.
//   - Header is the report's calibration line: model, tier, date, seed,
//     task set and prompt version, then the context probe that stopped
//     early and why, if one did, then the classes whose findings were
//     unstable discoveries in earlier --stability scans.
//
// RecordStability (stability.go, ADR 0024) keeps, beside each calibration
// and signed the same way, the per-class counts of the findings
// --stability scans labeled and of the unstable ones. Its key is the
// calibration's key fields under its own domain, so it follows the model,
// client, seed, task set and prompts, and never reads as a calibration.
// It is bounded (calibrated classes only, 256 findings a class, halved
// past it), expires with MaxAge, and starts afresh from any record creep
// cannot trust. It never changes a tier.
//
// The CLI (#14) must build Options.Model on models.Through(egressLog,
// client) and give calibration its own redact.Redactor, separate from the
// scan's, so calibration markers never mix with repository markers.
package calibrate
