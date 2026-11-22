package actionscripts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const marker = "<!-- creep-action:pr-comment -->"

// fakeCommentGH lists $FAKE_IDS for the comment lookup and, for a POST or
// PATCH, records the method and path and copies the body file it was sent.
const fakeCommentGH = `printf '%s\n' "$@" >>"$FAKE_DIR/calls"
method=GET path="" body=""
while [ $# -gt 0 ]; do
  case "$1" in
    --method) method="$2"; shift ;;
    -F) body="${2#body=@}"; shift ;;
    repos/*) path="$1" ;;
  esac
  shift
done
if [ "$method" = GET ]; then
  [ -z "${FAKE_IDS:-}" ] || printf '%s\n' "$FAKE_IDS"
  exit 0
fi
echo "$method $path" >"$FAKE_DIR/write"
cp "$body" "$FAKE_DIR/body"
`

func commentSandbox(t *testing.T, report string) (*sandbox, string) {
	t.Helper()
	s := newSandbox(t)
	s.fake("gh", fakeCommentGH)
	dir := t.TempDir()
	md := filepath.Join(t.TempDir(), "report.md")
	mustWrite(t, md, report, 0o600)
	s.env = map[string]string{"FAKE_DIR": dir, "GH_TOKEN": "t", "REPOSITORY": "owner/app", "PR_NUMBER": "7",
		"EXIT_CODE": "1", "MARKDOWN": md}
	return s, dir
}

// One comment per pull request: created when no comment of the bot starts
// with the marker, updated in place (the first match) otherwise. The lookup
// matches the bot's login and the marker, so a comment someone else wrote
// with the marker is never edited.
func TestCommentUpdatesInPlace(t *testing.T) {
	tests := []struct {
		name      string
		ids       string
		wantWrite string
	}{
		{"first run creates", "", "POST repos/owner/app/issues/7/comments"},
		{"later run updates", "11", "PATCH repos/owner/app/issues/comments/11"},
		{"duplicates update the first", "11\n12", "PATCH repos/owner/app/issues/comments/11"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := commentSandbox(t, "# creep report\n")
			s.env["FAKE_IDS"] = tt.ids
			wantCode(t, s.run("comment.sh"), 0, "")
			if got := strings.TrimSpace(mustRead(t, filepath.Join(dir, "write"))); got != tt.wantWrite {
				t.Errorf("wrote %q, want %q", got, tt.wantWrite)
			}
			calls := mustRead(t, filepath.Join(dir, "calls"))
			if !strings.Contains(calls, `select(.user.login == "github-actions[bot]" and (.body | startswith("`+marker+`")))`) {
				t.Errorf("lookup does not match the bot and the marker:\n%s", calls)
			}
		})
	}
}

// Protection (ADR 0023): the body is the marker, fixed text chosen by exit
// code and creep's Markdown report byte for byte (creep escapes repository
// and model text into code spans); the Action adds nothing from the report
// or the event. A long report is cut at a line boundary under GitHub's
// limit, with a note.
func TestCommentBody(t *testing.T) {
	hostile := "| `a` | `@team <img src=x> <!-- creep-action:pr-comment -->` |\n"
	long := strings.Repeat("| `sink-1` | `sqli` | `probable` | `app.py:16` |  |\n", 2000)
	tests := []struct {
		name     string
		code     string
		report   string
		wantHead string
		wantCut  bool
	}{
		{"gate", "1", hostile, "**Gate exceeded** (exit 1)", false},
		{"incomplete fails like the gate", "4", hostile, "**Incomplete run** (exit 4): not everything was evaluated, so this fails like a gate failure.", false},
		{"clean", "0", "# creep report\n", "**Nothing blocking** (exit 0).", false},
		{"unknown code", "9", "# creep report\n", "**Unexpected exit code**", false},
		{"long report is cut", "1", long, "**Gate exceeded** (exit 1)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := commentSandbox(t, tt.report)
			s.env["EXIT_CODE"] = tt.code
			wantCode(t, s.run("comment.sh"), 0, "")
			body := mustRead(t, filepath.Join(dir, "body"))
			head := marker + "\n### creep\n\n" + tt.wantHead
			if !strings.HasPrefix(body, head) {
				t.Fatalf("body starts %q, want %q", firstLines(body), head)
			}
			_, report, _ := strings.Cut(body, "\n\n"+tt.wantHead)
			_, report, _ = strings.Cut(report, "\n\n")
			checkReportPart(t, report, tt.report, tt.wantCut)
		})
	}
}

func checkReportPart(t *testing.T, got, report string, cut bool) {
	t.Helper()
	if !cut {
		if got != report {
			t.Errorf("report part %q, want the report byte for byte %q", got, report)
		}
		return
	}
	kept, note, ok := strings.Cut(got, "\n_Report cut to fit a comment;")
	if !ok || !strings.HasSuffix(note, "\n") {
		t.Fatalf("cut report has no note:\n%s", got[max(0, len(got)-200):])
	}
	if len(kept) > 60000 || !strings.HasPrefix(report, kept) || !strings.HasSuffix(kept, "\n") {
		t.Errorf("kept %d bytes: not a whole-line prefix of the report under 60000 bytes", len(kept))
	}
}

func firstLines(s string) string {
	lines := strings.SplitN(s, "\n", 5)
	return strings.Join(lines[:min(4, len(lines))], "\n")
}

func TestCommentWithoutReport(t *testing.T) {
	s, dir := commentSandbox(t, "")
	s.env["MARKDOWN"], s.env["EXIT_CODE"] = "", "2"
	wantCode(t, s.run("comment.sh"), 0, "")
	if body := mustRead(t, filepath.Join(dir, "body")); !strings.HasSuffix(body, "\n\n_creep wrote no report for this run._\n") {
		t.Errorf("body %q", body)
	}
}

// Values from the event and the API are checked before use: none can
// steer the API path or the comment that gets edited.
func TestCommentRefusesBadValues(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"pull request number with a path", map[string]string{"PR_NUMBER": "7/../../x"}, "no pull request number"},
		{"empty pull request number", map[string]string{"PR_NUMBER": ""}, "no pull request number"},
		{"repository with a query", map[string]string{"REPOSITORY": "owner/app?x=1"}, "no repository name"},
		{"exit code with text", map[string]string{"EXIT_CODE": "1 && id"}, "no creep exit code"},
		{"comment id from the API with a path", map[string]string{"FAKE_IDS": "11/../../x"}, "unexpected comment id"},
		{"report that is a device", map[string]string{"MARKDOWN": "/dev/null"}, "not a regular file"},
		{"report that is a link", map[string]string{"MARKDOWN": "link"}, "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := commentSandbox(t, "# creep report\n")
			for k, v := range tt.env {
				s.env[k] = v
			}
			if s.env["MARKDOWN"] == "link" {
				target := filepath.Join(t.TempDir(), "elsewhere.md")
				mustWrite(t, target, "# creep report\n", 0o600)
				s.env["MARKDOWN"] = filepath.Join(t.TempDir(), "report.md")
				if err := os.Symlink(target, s.env["MARKDOWN"]); err != nil {
					t.Fatal(err)
				}
			}
			wantCode(t, s.run("comment.sh"), 1, tt.want)
			if _, err := os.Stat(filepath.Join(dir, "write")); err == nil {
				t.Fatal("a comment was written")
			}
		})
	}
}

// Protection (ADR 0023, #29 auditor note): exit 4 fails the job exactly as
// a gate failure does, and every code but 0 fails it.
func TestVerdict(t *testing.T) {
	for _, tt := range []struct {
		code     string
		wantCode int
		want     string
	}{
		{"0", 0, "nothing blocking"},
		{"1", 1, "gate exceeded"},
		{"2", 1, "configuration"},
		{"3", 1, "model"},
		{"4", 1, "incomplete run (exit 4)"},
		{"", 1, "the scan did not run"},
		{"137", 1, "unexpected exit code"},
	} {
		t.Run(fmt.Sprintf("exit %q", tt.code), func(t *testing.T) {
			s := newSandbox(t)
			s.env["EXIT_CODE"] = tt.code
			wantCode(t, s.run("verdict.sh"), tt.wantCode, tt.want)
		})
	}
}
