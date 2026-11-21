// Package redact replaces secrets and personal data with stable markers before
// any text leaves the machine.
//
// It exists because creep sends fragments of the scanned repository to a
// model, and the repository can hold credentials and personal data. The
// gateway runs every payload through a Redactor first (AGENTS.md invariant 2).
//
// Detection:
//   - Secrets: the gitleaks default rules (rules/gitleaks.toml), vendored byte
//     for byte from a pinned release and evaluated with the standard regexp
//     package, so gitleaks is data, not a dependency. Version, URL and MIT
//     license are in NOTICE; a test pins the file's SHA-256 and rule count.
//   - Secrets the vendored rules miss: local rules in the same format
//     (rules/local.toml), so gitleaks.toml stays upstream. They cover Docker
//     access tokens (dckr_pat_, dckr_oat_), Discord webhook ids and tokens,
//     and OpenAI scoped keys (sk-proj-, sk-svcacct-, sk-admin-). The vendored
//     openai-api-key rule ends in \b, which fails after a key whose last
//     character is "-"; it is the only vendored rule with a \b right after a
//     possible "-" (TestTrailingBoundaryAfterDash fails if a re-vendor adds
//     one). A local id may not repeat a vendored one.
//   - PII: email addresses, card numbers (Luhn), US SSNs (dashed, SSA-valid
//     ranges), Spanish DNI and NIE (control letter) and Brazilian CPF (two
//     check digits, dotted or not). Checksums keep ordinary numbers in code
//     unmasked. An address needs a dotted domain (user@host is not one), and
//     the user git at a well-known git host, matched as the whole domain
//     (github.com, gitlab.com, bitbucket.org, ...), is an SSH remote
//     (git@github.com:org/repo), not a person's.
//   - Credentials with no fixed format, which gitleaks misses: the password
//     in scheme://user:password@host, the value of password, passwd, pwd,
//     passphrase and secret keys (see below for the values left alone), and
//     a bare 40-character AWS secret key when an AWS access key id is in the
//     same input, anywhere in the file for File (credentials.go). A value
//     assigned through
//     a subscript whose key names a credential (x['SECRET_KEY'] = '…',
//     headers["X-Api-Key"] = "…", config[:api_key] = '…'), which the
//     vendored generic rule misses at the closing "]" (subscript.go). A
//     value compared with such a key where the generic rule misses it too
//     (compare.go): through "!=", "!==", "<>", "≠" or ".equals(", through a
//     subscript or a call with the key as its only argument (secret !==
//     "…", os.environ["API_KEY"] == "…", os.getenv("TOKEN") != "…"), or
//     behind a shell quote ("$API_TOKEN" != "…"), when it has the generic
//     rule's shape; under a password or secret word at any length, as
//     assigned (password == "hunter2!").
//   - Private keys cut by a fragment boundary, which the gitleaks rule misses
//     because it needs BEGIN and END in the same text (pem.go). After a BEGIN
//     ... PRIVATE KEY line (any variant, PGP BLOCK included) everything is
//     masked through the matching END line or the end of the fragment; before
//     an END line, back to its BEGIN line or the start of the fragment. A key
//     body with neither (a middle fragment) is masked as a run of two or more
//     lines ending in a base64 token of 40 to 76 characters (lengths may
//     differ, since a boundary leaves partial lines), or one such line that
//     reaches the start or end of the fragment, directly or through one short
//     partial line; the run takes in a short line on either side. Prefixed digests
//     (go.sum "h1:", "sha256:") and lowercase hex do not count. A line may be a
//     string literal ("MIIE...\n" +, adjacent literals, a JSON value with "\n"
//     escapes, which also end a line, or a one-line array or concatenation
//     of literals, whose separators end a line the same way: ", ", ','
//     and "; " with up to four blanks, " + ", adjacent "..." "...", raw
//     `...`, prefixed b"..." and escaped \", \" quotes). A header or footer
//     line cut at the edge of the fragment ("-----END RSA PRIV") anchors the
//     body lines next to it, even one shorter than 40 bytes (pem_edge.go).
//     This can mask ordinary data, which is the safe side. Each line is read
//     once; the densest splits (a separator every four or five bytes) cost
//     two to three times repository code per byte
//     (BenchmarkPrivateKeysWorstCase against BenchmarkPrivateKeysRepoCode).
//   - A quoted password value is masked unless it only points at one (${VAR},
//     $VAR, {{ var }}, <placeholder>, %s, getPassword()). A bare one is kept
//     only when it is code (reference.go, #71): None, null, nil, true and
//     false; a number under a key whose last word measures the password
//     (PASSWORD_MIN_LENGTH = 12; DB_PASSWORD=123456 and PASSWORD_ADMIN=1234
//     are masked); a known type name after ":", alone or around another one
//     (password: string, Optional[str]); a dotted path of names, no digit,
//     whose first segment is, spelled exactly so, one of the config and
//     environment receivers cfg, config, conf, settings, os, process, env,
//     environ, options, opts, params, args, request and props
//     (process.env.SECRET_KEY, cfg.Secret; self.password is masked); a call or subscript left open, its arguments so far names
//     without digits, ending at a comma or a quote and closed later on the
//     line (GenerateFromPassword(pw, cost), os.environ["X"]); a shell
//     variable right before a path, no blank ("$PWD:/src"). The literals
//     after a kept value on its line are masked (None or "x",
//     os.environ.get("X", "default"), str = "x"), except the first argument
//     of a lookup, which names what it reads; the read stops at a comment
//     and reads each line once. A value in a shape that only resembles code
//     (hunter(2), real(PW99 + x), Optional[x99], monkey.island.sunset,
//     this.is.sparta, user.password) is masked.
//   - The generic-api-key rule skips a word compared with == or === (key ===
//     "constructor"): letters, "_", "." and "-" only, as in the gitleaks
//     allowlist, so a passphrase of words compared with any credential key
//     is sent (if password == "CorrectHorseBatteryStaple"); compare.go keeps
//     the same exemption for the comparisons it reads. Assigned values, and
//     compared values with any digit or other character (under the generic
//     words, from 10 bytes), are still masked.
//     It also skips a dotted path of such words read from a known receiver
//     (process.env.SECRET_KEY, cfg.Secret).
//
// When matches overlap they are merged into one masked span, and a fixed
// precedence names it: a rule that knows the secret's format, then the
// password detector, then the generic-api-key rule, then PII, then the
// sweep; a tie goes to the label that sorts first, so File and Redact name
// the same span alike whatever order the detectors ran in. A secret that
// only personal data reaches past (a URL password whose tail and host read
// as an email) keeps its own marker and the bytes on either side get theirs,
// so the password has one marker inside the URL and on its own, in either
// order. Each part is also remembered, so it is masked when it shows up
// alone in a later fragment.
//
// Format characters: a zero-width space, joiner or other Unicode format
// character (category Cf) inside a token renders as nothing but breaks every
// rule. Each Redact and File call whose input holds one outside a leading
// run runs every detector and the sweep twice: on the text, and on a copy
// without format characters whose spans map back onto the original bytes,
// so the mask covers the whole token, format characters inside it included
// (format.go). The bytes sent change only where they are masked. A value
// masked with format characters inside is also remembered without them.
// Searching the original too keeps a match that the removal would break (a
// key id followed by a zero-width space and a word), though not when the
// token also holds one inside (see Detection limits). A leading run of them,
// such as a byte order mark, joins nothing, so it costs no second pass.
//
// Detection limits: what follows is not masked, or not always. Each needs a
// secret written in a shape no rule knows, mostly on purpose by whoever wrote
// the code; covering it would mask large amounts of ordinary code or cost a
// pass per shape.
//   - Concatenated tokens: a token built from pieces ("ghp_" + "abc...",
//     adjacent literals, a join or format call) is matched piece by piece,
//     and a piece is masked only if it matches a rule alone. Joining literals
//     would need a pass per language's syntax over ordinary code.
//   - Short values: values of fewer than 8 bytes (minSweepLen) are masked
//     where a rule matches them, but not re-masked where they show up later
//     without their key, since a short value occurs inside ordinary words.
//   - AWS ordering: a bare 40-character AWS secret key is masked only when an
//     access key id is in the same Redact input or File call. If the id only
//     comes in a later file, the secret has already been sent. Masking every
//     40-character base64 run would mask paths and identifiers of that length.
//     A secret key next to its usual name (aws_secret_access_key,
//     SecretAccessKey) is masked by the password and generic rules anyway.
//   - A format character at a token's edge next to a word character, plus
//     one inside the token ("word", U+200B, "AK", U+200B, "IA..."), gets past
//     a rule anchored on \b, such as the AWS key id: the original text has
//     the inner one, and the copy glues the token to the word. That reads
//     like a key glued to a word, which such a rule misses in plain text too.
//     Rules with no boundary (GitHub, Slack) still match. Telling an edge
//     from an inside character would take a third pass per shape.
//   - Other invisible or look-alike characters: only category Cf is removed.
//     Invisible characters outside it, such as variation selectors (U+FE0F,
//     U+E0100), the combining grapheme joiner (U+034F), the Mongolian free
//     variation selectors (U+180B), Khmer inherent vowels (U+17B4), Hangul
//     fillers (U+3164, U+115F), the braille blank (U+2800) and unusual
//     spaces, and homoglyphs (a Cyrillic er for the "p" of "ghp_") break a
//     rule, and so do encodings other than the separators listed below.
//   - A value split from its key by other text (see Performance).
//   - A compared value before its key ("…" == token, "…".equals(token)), or
//     in a triple-quoted literal; a key body in an array whose separator
//     holds more than four blanks on a side or a no-break space.
//   - Fragments only: a key body with no header or footer whose first line
//     follows an assignment prefix (KEY = "MIIE..., {"private_key": "...)
//     can leave that first line visible when Redact runs on a fragment cut
//     next to it (#190). File on the whole file masks it, and callers send
//     only File output (see Whole files).
//   - Literals the password detector leaves next to code (#71), as main did
//     before it: the first argument of a lookup or getter
//     (getSecret("..."), d["..."], os.environ['...']), which is taken for the
//     name it reads; a value on a later line than its key or call
//     (os.environ.get(\n "X", "..."), password=(\n"..."), a line
//     continuation, YAML block scalars "|" and ">-", anchors and tags); a
//     literal after "#" or "//" outside a string, read as a comment
//     (cfg.Secret || this.#x || "..."); a literal glued to a kept value
//     (None"..."); a no-break space before "=", and curly quotes.
//   - A digit-free dotted passphrase that starts with one of the receivers
//     above (config.is.sparta, env.monkey.island) reads as a config path and
//     is sent; the password and generic rules both keep it (#71).
//   - A value repeated in the same input: a value a rule finds only by its
//     context (a URL password, a key's value) and that shows up again
//     without that context later in the same Redact or File call is not
//     masked there, at any length. The sweep re-masks only values stored by
//     earlier calls, so the repeat is masked from the next call on.
//
// The rules file is read by a tiny reader for the TOML subset it uses
// (toml.go) instead of a generator that converts it to JSON. Both need the same
// parsing, but this way the embedded file stays identical to upstream and can
// be verified by hash, there is no second artifact to keep in sync, and any
// syntax outside the subset is an error caught by the tests: an unknown or
// repeated key, a rule key (id, regex, secretGroup, keywords) after an
// allowlist block, where TOML would give it to the allowlist, and an indented
// line outside a multi-line array. Only id, regex,
// secretGroup and keywords are used. Keywords gate rules exactly as in
// gitleaks (a rule runs only if one of its keywords occurs, case-insensitive);
// without that, running every regex on every fragment is far too slow.
// Entropy thresholds and allowlists are ignored on purpose: they exist to cut
// false positives in reports, while a redactor should rather mask too much
// than leak. Matches may overlap, so a lazy match opened by earlier text cannot
// end inside a real secret and hide the rest of it. Like gitleaks, the masked
// value is the secret group (or the first non-empty group), so variable names
// and quotes around it stay readable for the model.
//
// Markers: each distinct value gets <SECRET_<RULE>_<N>> or <PII_<KIND>_<N>>,
// numbered per kind, and keeps it for the life of the Redactor (one per run),
// so the same secret has the same marker in every fragment. Values seen before
// are also masked where no rule matches them any more. The reverse map lives
// only in memory: it has no exported field, no encoding method, prints as a
// fixed string, and the package imports nothing that writes files (enforced by
// a test). Unredact is for local display only.
//
// Marker-like text already present in the input ("<SECRET_", "<PII_",
// "<ESC_") is escaped by inserting ESC_, so repository text can neither forge a
// marker that un-redacts to a real secret nor collide with one.
//
// Whole files: File redacts a file before anything cuts it, so a secret is
// never seen split across fragments. Callers that fragment repository text
// (the gateway, #3, and the reader, #13) must fragment only text returned by
// File, never raw file content: the per-fragment detectors in Redact can only
// guess at a key or token a boundary cut, and a guess can miss (a partial
// line of a key body, a token's tail with no prefix). File finds private keys
// over the whole file (from BEGIN to END, BEGIN to the end of the file, the
// start of the file to END, and bare key bodies). It also runs over the whole
// file the rules whose matches have no byte bound back from their last line
// (wholeFileRules: the private-key rule, base64 JWTs wrapped over lines, the
// two curl rules, whose continuation lines may be of any length, and the
// freemius, kubernetes and nuget rules, which reach through a run of blanks
// of any length). A match and the restarts after it can now run past 64 KiB,
// so on some input crafted for those rules, even with no format character, a
// whole-file pass may cost more than chunks did. It stays linear, since the
// restart budget scales with the text, and far under the every-keyword worst
// case on MaxFileBytes (BenchmarkFileWholeFileRules times the crafted curl
// and freemius shapes). It runs every other detector on
// chunks of at most
// MaxInputBytes that end at line ends, each
// reaching chunkOverlap (4 KiB) to twice that back into the previous one; a
// chunk starts inside a line only when a long line straddles that reach, so
// long lines cannot make chunks re-scan most of a file. Every line lies in
// one chunk with the 4 KiB before it, and no chunked detector reaches more
// than a few hundred bytes back from its last line (derived per regex by
// TestChunkOverlapBound, which also fails if a rule over that bound is not a
// whole-file rule), so every match is seen whole by the whole-file pass or by
// some chunk. Spans
// from all chunks are merged before markers are written, so a value found
// twice in an overlap is masked once and keeps one marker for the run.
// Redact still applies every detector to each fragment, as defense in depth.
//
// Performance: Go's regexp is linear-time (RE2), so no input can trigger
// catastrophic backtracking. Each Redact call is still bounded to
// MaxInputBytes, each File call to MaxFileBytes (1 MiB) with lines of at most
// MaxLineBytes, and both fail closed above their caps. The constants document
// the measured worst case. That worst case is minutes per file, so a
// Redactor from NewWithContext stops between detectors and chunks once the
// run's context is done (the scan deadline, #260) and returns no text.
// Values from earlier fragments are re-masked through
// an index of 8-byte windows, linear in the input however many values the run
// knows. A rule whose matches overlap densely (a block of .env lines with
// long names) stops searching again after a fixed multiple of the input,
// masks the rest of the current line and searches the next lines with a
// budget of the bytes it masked, so the dense block hides only its own lines
// and the code after it stays visible. When that rule can match a newline
// and the masked line ends in an assignment ("db_password =") or the next line
// starts with one, the next line that holds text is masked too, since a match
// starting in the masked part could carry its value there. A value split from
// its key some other way, such as by a line of text in between, is not
// followed (a known limit). After a hard total of one more input length, the
// rest of the input is masked instead. The masked guesses are not remembered
// as values.
//
// Encoded separators: URL-shaped rules (a literal "/" in the regex, such as
// the Discord, Slack and Teams webhook rules) run again on a copy of the text
// with these separators decoded, in either case: "\/" after one to seven
// backslashes (JSON, and JSON nested in JSON), the JSON escapes \u002F and
// \u003A, "%2F", "%3A" and their double encodings "%252F" and "%253A", and
// the HTML entities "&#x2F;", "&#47;", "&sol;", "&#x3A;", "&#58;" and
// "&colon;". Each match maps back onto the original bytes, so every byte of
// an encoded webhook URL's secret is masked, escapes included, and the
// vendored rules stay byte for byte upstream. Each position looks at a fixed
// number of bytes, so decoding stays linear. Other encodings (HTML entities
// without the final ";", triple percent-encoding, base64) are not decoded.
//
// Run limits: one run remembers at most about 128k values or 32 MiB of them
// (a private key without an END line is one value up to the end of its file,
// counted about once: TestFileKeyCountsOnce), and at most 256 values whose
// every 8-byte window already indexes 16 others (runs of one byte or short
// pattern, such as "xxxxxxxx" placeholders). When a new value does not fit,
// that call and every later call on the Redactor return ErrRunFull and no
// output, because a value the run cannot remember would not be re-masked in
// later fragments. Callers must stop sending that run's fragments and report
// the scan as incomplete.
//
// Per-call share: one Redact or File call may add at most a quarter of the
// run's values or bytes and 32 overflow values (share.go), so one crafted file
// cannot fill the run. A call over its share returns ErrTooManyValues and no
// output, and everything it stored is rolled back; the run goes on. The
// gateway lists that file as not scanned (redact_failed), never sends it.
// Eight files each at the overflow share still fill the overflow list and end
// the run (TestOverflowListLimitIsPinned).
package redact
