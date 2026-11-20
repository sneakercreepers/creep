package redact

import (
	"strings"
	"testing"
)

// Code that handles passwords is what a security scan must read: none of it
// holds a secret, so it reaches the model unchanged (#71).
func TestRedactKeepsPasswordHandlingCode(t *testing.T) {
	tests := []struct{ name, text string }{
		{"measure number", "PASSWORD_MIN_LENGTH = 12"},
		{"measure camel case", "passwordHashRounds: 10,"},
		{"measure ttl", "SECRET_TTL=3600"},
		{"python None", "password = None"},
		{"js null", "let password = null;"},
		{"go nil", "secret := nil"},
		{"boolean", "password_required: true"},
		{"type annotation", "  password: string;"},
		{"python type", "def login(password: str) -> bool:"},
		{"generic type", "password: Optional[str] = None"},
		{"subscript lookup", `secret = os.environ["X"]`},
		{"env lookup", `password = os.getenv("DB_PASSWORD")`},
		{"config lookup", `secret = config.get("app.secret")`},
		{"prompt", `password = getpass.getpass("Password: ")`},
		{"call with argument", "hash, err := bcrypt.GenerateFromPassword(pw, cost)"},
		{"call assigned", "pwd := GenerateFromPassword(pw, 10)"},
		{"shell path", `docker run --rm -v "$PWD:/src" -w /src golang`},
		{"shell var in a string", `docker run -e "DB_PASSWORD=$DB_PASSWORD" -v "a b" img`},
		{"env path", "const secret = process.env.SECRET_KEY;"},
		{"env path generic", "api_key = process.env.API_KEY"},
		{"config field", "secret := cfg.Secret"},
		{"config field generic", "apiKey = cfg.Secret"},
		{"object field", "this.password = user.password;"},
		{"git remote", "git clone git@github.com:org/repo.git"},
		{"self-hosted git remote", "url = git@gitlab.example.com:team/app.git"},
		{"user at host", "ssh user@host"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out := mustRedact(t, newRedactor(t), tc.text); out != tc.text {
				t.Fatalf("Redact(%q) = %q, want unchanged", tc.text, out)
			}
		})
	}
}

// The exemptions keep code, never a secret written out: a literal next to a
// kept reference, a literal under the same names, and shapes that only look
// like code are still masked.
func TestRedactExemptionsKeepSecretsHidden(t *testing.T) {
	pw := propPassword
	tests := []struct{ name, text string }{
		{"None or literal", `password = None or "PW"`},
		{"None if else", `password = None if debug else 'PW'`},
		{"f-string fallback", `password = None or f'PW'`},
		{"open literal", `password = None or "PW`},
		{"field assigned a literal", `cfg.Secret = "PW"`},
		{"lookup default", `SECRET = os.environ.get("X", "PW")`},
		{"lookup or literal", `password = os.getenv("X") or "PW"`},
		{"env path fallback", `const secret = process.env.SECRET_KEY || "PW";`},
		{"call of a literal", `password = decrypt("PW")`},
		{"concatenation", `secret := cfg.Secret + "PW"`},
		{"typed python", `password: str = "PW"`},
		{"typed ts", `password: string = 'PW';`},
		{"plain number", "DB_PASSWORD=12345678"},
		{"pin number", "pin_password: 424242"},
		{"quoted None", `password = "None"`},
		{"quoted type", `password: "string"`},
		{"type word after =", "password = string"},
		{"digit call", "password: hunter(2)"},
		{"bracket in a password", "password: t8wMWwtM6z(!d%5r"},
		{"subscript in a password", "DB_PASSWORD=abcd[efgh"},
		{"dotted passphrase", "password: correct.horse.battery"},
		{"php variable", `$password = "PW";`},
		{"shell var not a path", "$PASSWORD: PW"},
		{"person at a git host", "author: alice@github.com"},
		{"git user elsewhere", "contact git@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.ReplaceAll(tc.text, "PW", pw)
			out := mustRedact(t, newRedactor(t), text)
			if out == text {
				t.Fatalf("Redact(%q) left it unchanged", text)
			}
			if strings.Contains(tc.text, "PW") && strings.Contains(out, pw[:6]) {
				t.Fatalf("Redact(%q) = %q: the literal leaked", text, out)
			}
		})
	}
}

// A number is masked unless the key measures the password, and a dotted
// generic value needs a word that reads as config and no digit.
func TestJudgeBare(t *testing.T) {
	tests := []struct {
		key, value, after string
		want              bareVerdict
	}{
		{"PASSWORD_MIN_LENGTH = ", "12", "", keepReference},
		{"PASSWORD = ", "12", "", maskValue},
		{"password: ", "string", ";", keepReference},
		{"password = ", "string", "", maskValue},
		{"$PWD:", "/src", `" x`, keepValue},
		{"$PWD = ", "/src", "", maskValue},
		{"secret = ", "os.environ[", `"X"]`, keepLookup},
		{"secret = ", "os.environ[", "", maskValue},
		{"secret = ", "decrypt(", `"x")`, keepReference},
		{"secret = ", "Getenv(", `"X")`, keepLookup},
		{"pwd := ", "GenerateFromPassword(pw", ", 10)", keepReference},
		{"password: ", "t8wMWwtM6z(!d%5r", "", maskValue},
		{"password: ", "abc(def)", " x)", maskValue},
		{"password = ", "hunter(2)", "", maskValue},
		{"password = ", "user.password", "", keepReference},
		{"password = ", "user.name", "", maskValue},
		{"password = ", "user.password2", "", maskValue},
		{"password = ", "${DB_PASSWORD}", "", keepReference},
	}
	for _, tc := range tests {
		if got := judgeBare(tc.key, tc.value, tc.after); got != tc.want {
			t.Errorf("judgeBare(%q, %q, %q) = %d, want %d", tc.key, tc.value, tc.after, got, tc.want)
		}
	}
}

// A URL password has one marker whether it shows up inside the URL or on
// its own, in either order, in the same call or a later one, and Unredact
// still restores each call exactly (#71).
func TestURLPasswordOneMarker(t *testing.T) {
	pw := urlPassword + "x"
	url := "postgres://admin:" + pw + "@db.internal\n"
	alone := "DB_PASSWORD=" + pw + "\n"
	tests := []struct {
		name  string
		calls []string
	}{
		{"url then alone", []string{url, alone}},
		{"alone then url", []string{alone, url}},
		{"one call, url first", []string{url + alone}},
		{"one call, alone first", []string{alone + url}},
		{"url then bare later", []string{url, "pw " + pw + " "}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRedactor(t)
			markers := map[string]bool{}
			for _, text := range tc.calls {
				out := mustRedact(t, r, text)
				if strings.Contains(out, pw) {
					t.Fatalf("password leaked: %q", out)
				}
				if back := r.Unredact(out); back != text {
					t.Fatalf("Unredact(%q) = %q, want %q", out, back, text)
				}
				for _, m := range passwordMarkers(out) {
					markers[m] = true
				}
			}
			if len(markers) != 1 {
				t.Fatalf("password markers %v, want one", markers)
			}
		})
	}
}

// passwordMarkers returns the URL_PASSWORD and PASSWORD markers in text.
func passwordMarkers(text string) []string {
	var out []string
	for _, part := range strings.Split(text, "<")[1:] {
		m, _, _ := strings.Cut(part, ">")
		if strings.HasPrefix(m, "SECRET_URL_PASSWORD_") || strings.HasPrefix(m, "SECRET_PASSWORD_") {
			out = append(out, m)
		}
	}
	return out
}

// A value under a key both the password detector and the generic rule know
// takes one label whatever order the spans arrive in, so File and Redact
// agree (tester cycle 5 on #71).
func TestMergedLabelIsFixed(t *testing.T) {
	text := "secret = " + strings.Repeat("Ab3x", 5) + "\n"
	want := "secret = <SECRET_PASSWORD_1>\n"
	if out := mustRedact(t, newRedactor(t), text); out != want {
		t.Errorf("Redact = %q, want %q", out, want)
	}
	if out := mustFile(t, newRedactor(t), text); out != want {
		t.Errorf("File = %q, want %q", out, want)
	}
	pairs := [][2]string{
		{genericLabel, passwordLabel},
		{"SECRET_B_RULE", "SECRET_A_RULE"},
		{"PII_EMAIL", genericLabel},
	}
	for _, p := range pairs {
		a := mergeSpans([]span{{0, 4, p[0], false}, {0, 4, p[1], false}})
		b := mergeSpans([]span{{0, 4, p[1], false}, {0, 4, p[0], false}})
		if a[0].label != b[0].label {
			t.Errorf("labels %v: %s in one order, %s in the other", p, a[0].label, b[0].label)
		}
	}
}

// tailLiterals masks each literal's contents, stops at a comment, takes an
// apostrophe for one and masks the rest of the line after an open "\"".
func TestTailLiterals(t *testing.T) {
	tests := []struct{ line, want string }{
		{` or "abc"`, ` or "#"`},
		{` or "a\"b" + 'c'`, ` or "#" + '#'`},
		{` or f'abc'`, ` or f'#'`},
		{` # don't "abc"`, ` # don't "abc"`},
		{` // "abc"`, ` // "abc"`},
		{` or "" + "abc`, ` or "" + "#`},
		{` isn't "abc"`, ` isn't "#"`},
		{` x' or "abc"`, ` x' or "#"`},
		{` '\'\'\' or "abc"`, ` '\'\'\' or "#"`},
	}
	for _, tc := range tests {
		padded := "\n" + tc.line + "\n"
		spans, end := tailLiterals(padded, 1, passwordLabel)
		if end != len(padded)-1 {
			t.Errorf("%q: line end %d, want %d", tc.line, end, len(padded)-1)
		}
		got, prev := "", 0
		for _, sp := range spans {
			got += tc.line[prev:sp.start] + "#"
			prev = sp.end
		}
		if got += tc.line[prev:]; got != tc.want {
			t.Errorf("tailLiterals(%q) masks %q, want %q", tc.line, got, tc.want)
		}
	}
}
