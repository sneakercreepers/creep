package state

import (
	"os"
	"path/filepath"
	"testing"
)

// Pentest P7: Open leaves a .gitignore that ignores the whole directory, and
// never rewrites or follows an entry already named .gitignore.
func TestOpenIgnoresStateInGit(t *testing.T) {
	tests := []struct {
		name    string
		planted string // "" means no .gitignore before Open
		want    string
	}{
		{"new directory", "", "# Written by creep: run state, egress.log and reports stay local.\n*\n"},
		{"existing file kept", "!egress.log\n", "!egress.log\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".creep")
			if tt.planted != "" {
				if err := os.Mkdir(dir, dirMode); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(tt.planted), fileMode); err != nil {
					t.Fatal(err)
				}
			}
			s, err := Open(dir, testSecret)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
			if err != nil || string(got) != tt.want {
				t.Fatalf(".gitignore = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}
