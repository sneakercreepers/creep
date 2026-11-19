package repofile

import "testing"

// bs is one backslash, so the expected escapes below read as written.
const bs = "\\"

func TestEscapeLines(t *testing.T) {
	tests := []struct{ in, want string }{
		{"\tplain ascii = 1", "\tplain ascii = 1"},
		{"caf\xc3\xa9 \xe2\x9c\x93", "caf\xc3\xa9 \xe2\x9c\x93"},
		{"a\rb", "a" + bs + "x0db"},
		{"\x00\x7f", bs + "x00" + bs + "x7f"},
		{"\xe2\x80\x8b\xe2\x81\xa6x\xe2\x81\xa9", bs + "u200b" + bs + "u2066x" + bs + "u2069"},
		{"bad \xc3", "bad " + bs + "xc3"},
		{"\xc2\x85fake| line", bs + "x85fake| line"},
		{"\xe2\x80\xa8x", bs + "u2028x"},
	}
	for _, tt := range tests {
		if got := EscapeLines([]string{tt.in})[0]; got != tt.want {
			t.Errorf("EscapeLines(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
