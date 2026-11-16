package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Regression (pentest P1): a secret assigned through a subscript whose key
// names a credential is masked in every language creep reads, and the
// dict, object, hash and map literal forms stay masked. {v} is the secret.
func TestRedactSubscriptAssignments(t *testing.T) {
	v := fakeToken(rand.New(rand.NewPCG(31, 32)), alnum, 40)
	tests := []struct{ name, text string }{
		{"python flask config", "app.config['SECRET_KEY'] = '{v}'\n"},
		{"python double quotes", `app.config["SECRET_KEY"] = "{v}"` + "\n"},
		{"python no spaces", "app.config['SECRET_KEY']='{v}'\n"},
		{"python header", "    headers['X-Api-Key'] = '{v}'\n"},
		{"python environ", "os.environ['API_KEY'] = '{v}'\n"},
		{"python password", `creds["password"] = "{v}"` + "\n"},
		{"python bytes prefix", "cfg['api_token'] = b'{v}'\n"},
		{"python nested key first", "cfg['api_key']['prod'] = '{v}'\n"},
		{"python nested key last", "config['db']['password'] = '{v}'\n"},
		{"js config", "config['apiKey'] = '{v}';\n"},
		{"js process env", "process.env['API_TOKEN'] = '{v}';\n"},
		{"js template literal", "headers[`Authorization`] = `{v}`;\n"},
		{"ts nullish assign", "opts['accessToken'] ??= \"{v}\";\n"},
		{"ruby symbol", "config[:api_key] = '{v}'\n"},
		{"ruby or-assign", "ENV['SECRET_TOKEN'] ||= \"{v}\"\n"},
		{"php", "$config['api_key'] = '{v}';\n"},
		{"go map", "\tm[\"apiKey\"] = \"{v}\"\n"},
		{"bare value", "settings['token'] = {v};\n"},
		{"bearer header", "headers['Authorization'] = 'Bearer {v}'\n"},
		{"harmless key then credential", "cfg['api_url']['token'] = '{v}'\n"},
		{"author token", "row['author_token'] = '{v}'\n"},
		{"python dict literal", "cfg = {'api_key': '{v}'}\n"},
		{"js object literal", "const cfg = { apiKey: '{v}' };\n"},
		{"ruby hash", "cfg = { 'api_key' => '{v}' }\n"},
		{"php array", "$cfg = ['api_key' => '{v}'];\n"},
		{"go map literal", "m := map[string]string{\"apiKey\": \"{v}\"}\n"},
		{"python kwargs", "client = Client(api_key='{v}')\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.ReplaceAll(tc.text, "{v}", v)
			out := mustRedact(t, newRedactor(t), text)
			if strings.Contains(out, v) || !strings.Contains(out, "<SECRET_") {
				t.Fatalf("Redact(%q) = %q, want the value masked", text, out)
			}
		})
	}
}

// Near misses: comparisons, references and plain identifiers in a
// credential subscript stay readable.
func TestRedactSubscriptKeepsCode(t *testing.T) {
	tests := []string{
		"if x['password'] == 'abc':\n",
		"if (x['apiKey'] === 'constructor') {}\n",
		"headers['Authorization'] = settings.AUTH_HEADER\n",
		"cache['key'] = value\n",
		"os.environ['API_KEY'] = os.getenv('X')\n",
		"cfg['token'] = '${TOKEN}'\n",
		"cfg['token'] = ''\n",
		"items['name'] = 'widget-a1'\n",
		"x = data['api_key']\n",
		// Keys that contain a credential word without naming one (tester
		// on #231).
		"d['keyboard_layout'] = 'us'\n",
		"row['author'] = 'Jane Doe, 2nd edition'\n",
		"m['monkey'] = 'banana-split-2000'\n",
		"data['tokenizer'] = 'bert-base-uncased-v2'\n",
		"opts['api_version'] = '2023-05-01-preview'\n",
		"cfg['api_url'] = 'https://api.example.com/v1'\n",
		"cfg['token_type'] = 'Bearer'\n",
		"cfg['sort_key'] = 'created_at_2024'\n",
		// The generic value shape: a short word under a generic key.
		"headers['X-Api-Key'] = 'changeme'\n",
	}
	for _, text := range tests {
		if out := mustRedact(t, newRedactor(t), text); out != text {
			t.Errorf("Redact(%q) = %q, want unchanged", text, out)
		}
	}
}
