package scanrun

import "testing"

// TestTaskkillPath (#226): taskkill runs only from System32 under a
// drive-letter Windows directory, never from the current directory, a
// drive-relative path or a network share.
func TestTaskkillPath(t *testing.T) {
	tests := []struct {
		root, want string
	}{
		{`C:\Windows`, `C:\Windows\System32\taskkill.exe`},
		{`D:\WinNT\`, `D:\WinNT\System32\taskkill.exe`},
		{"", ""},
		{"Windows", ""},
		{`C:Windows`, ""},
		{`\\attacker\share`, ""},
		{`\\?\C:\Windows`, ""},
		{`\\.\C:\Windows`, ""},
	}
	for _, tt := range tests {
		got, ok := taskkillPath(tt.root)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("taskkillPath(%q) = %q, %v; want %q", tt.root, got, ok, tt.want)
		}
	}
}
