package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const (
	testMod = "example.com/creep"
	sdkMcp  = sdkModule + "/mcp"
)

// linkGraphOf builds a linker graph from "from -> to" lines.
func linkGraphOf(t *testing.T, lines ...string) linkGraph {
	t.Helper()
	g, err := parseLinkGraph(bytes.NewBufferString("# " + testMod + "/cmd/creep\n" + strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// Protection (#32, ADR 0027): no third-party code linked into creep may
// reach a function that opens a connection or starts a program, by any
// chain, unless the exact edge was reviewed. Each row is one way the SDK
// or a dependency of it could do so; the clean rows prove the walk does
// not flag what the gateway, the standard library or deduplicated
// funcdata link.
func TestLinkReachCatchesNet(t *testing.T) {
	gw := testMod + "/internal/gateway"
	reviewed := "github.com/modelcontextprotocol/go-sdk/oauthex.newDiscoveryTransport -> net/http.(*Transport).Clone"
	tests := []struct {
		name  string
		lines []string
		want  string // "" for no problem
	}{
		{"SDK dials", []string{sdkMcp + ".(*StreamableClientTransport).Connect -> net.(*Dialer).DialContext"}, "links net.(*Dialer).DialContext"},
		{"SDK through the standard library", []string{sdkMcp + ".(*Server).Run -> encoding/json.Marshal", "encoding/json.Marshal -> net/http.(*Client).Do"},
			sdkMcp + ".(*Server).Run -> encoding/json.Marshal -> net/http.(*Client).Do"},
		{"SDK starts a program", []string{sdkMcp + ".(*CommandTransport).Connect -> os/exec.(*Cmd).Start"}, "links os/exec.(*Cmd).Start"},
		{"raw process start", []string{sdkMcp + ".f -> os.StartProcess"}, "links os.StartProcess"},
		{"HTTP server", []string{sdkMcp + ".(*StreamableHTTPHandler).ServeHTTP -> net/http.(*response).Write"}, "links net/http.(*response).Write"},
		{"http2 internals", []string{sdkMcp + ".f -> net/http/internal/http2.(*Transport).RoundTrip"}, "links net/http/internal/http2"},
		{"TLS", []string{sdkMcp + ".f -> crypto/tls.Dial"}, "links crypto/tls.Dial"},
		{"dependency init", []string{"go:main.inittasks -> golang.org/x/oauth2..inittask", "golang.org/x/oauth2..inittask -> golang.org/x/oauth2.init", "golang.org/x/oauth2.init -> net/http.(*Client).Get"},
			"golang.org/x/oauth2.init -> net/http.(*Client).Get"},
		{"method behind a type descriptor", []string{sdkMcp + ".f -> type:*net/http.Client", "type:*net/http.Client -> net/http.(*Client).Do"}, "links net/http.(*Client).Do"},
		{"generic instance", []string{sdkMcp + ".AddTool[go.shape.struct { X int }] -> net.Dial"}, "links net.Dial"},
		{"reviewed edge", []string{reviewed}, ""},
		{"reviewed target reached another way", []string{reviewed, sdkMcp + ".g -> net/http.(*Transport).Clone"}, "links net/http.(*Transport).Clone"},
		{"funcdata named after net", []string{sdkMcp + ".f -> net/http.(*Transport).dial.stkobj", sdkMcp + ".g -> net.(*conn).Read.arginfo1"}, ""},
		{"type descriptor alone", []string{sdkMcp + ".f -> type:net/http.Header", sdkMcp + ".f -> go:itab.*net/http.Transport,net/http.RoundTripper"}, ""},
		{"main module is checked by import rules", []string{sdkMcp + ".f -> " + gw + ".dial", gw + ".dial -> net.Dial"}, ""},
		{"standard library alone", []string{testMod + "/cmd/creep.main -> net/http.(*Client).Do", "net/http.(*Client).Do -> net.Dial"}, ""},
		{"raw socket", []string{sdkMcp + ".f -> syscall.Socket"}, "links syscall.Socket"},
		{"raw connect through a helper", []string{sdkMcp + ".f -> encoding/json.Marshal", "encoding/json.Marshal -> syscall.Connect"}, "links syscall.Connect"},
		{"sendto", []string{sdkMcp + ".f -> syscall.Sendto"}, "links syscall.Sendto"},
		{"execve", []string{sdkMcp + ".f -> syscall.Exec"}, "links syscall.Exec"},
		{"fork and exec", []string{sdkMcp + ".f -> syscall.ForkExec"}, "links syscall.ForkExec"},
		{"Windows process", []string{sdkMcp + ".f -> syscall.CreateProcess", sdkMcp + ".g -> syscall.CreateProcessAsUser"}, "links syscall.CreateProcessAsUser"},
		{"x/sys socket", []string{sdkMcp + ".f -> golang.org/x/sys/unix.Socket"}, "golang.org/x/sys/unix.Socket"},
		{"x/sys wrapper of a socket", []string{"golang.org/x/sys/unix.Connect -> golang.org/x/sys/unix.connect", "golang.org/x/sys/unix.connect -> syscall.RawSyscall"}, "links golang.org/x/sys/unix.Connect"},
		{"x/sys exec", []string{"github.com/x/y.f -> golang.org/x/sys/unix.Exec"}, "golang.org/x/sys/unix.Exec"},
		{"x/sys Windows shell", []string{"github.com/x/y.f -> golang.org/x/sys/windows.ShellExecute"}, "golang.org/x/sys/windows.ShellExecute"},
		{"x/sys Windows socket", []string{"golang.org/x/sys/windows.WSASocket -> syscall.SyscallN"}, "links golang.org/x/sys/windows.WSASocket"},
		{"any x/sys/unix call", []string{sdkMcp + ".f -> golang.org/x/sys/unix.Getpid"}, "raw system call golang.org/x/sys/unix.Getpid"},
		{"raw syscall by number", []string{sdkMcp + ".f -> syscall.Syscall"}, "raw system call syscall.Syscall"},
		{"raw syscall6", []string{sdkMcp + ".f -> syscall.RawSyscall6"}, "raw system call syscall.RawSyscall6"},
		{"raw SyscallN", []string{sdkMcp + ".f -> syscall.SyscallN"}, "raw system call syscall.SyscallN"},
		{"DLL call by name", []string{sdkMcp + ".f -> syscall.(*LazyProc).Call"}, "raw system call syscall.(*LazyProc).Call"},
		{"standard library makes raw calls", []string{sdkMcp + ".f -> os.ReadFile", "os.ReadFile -> syscall.read", "syscall.read -> syscall.Syscall"}, ""},
		{"x/sys wrappers make raw calls", []string{"golang.org/x/sys/cpu.f -> syscall.Syscall6", "golang.org/x/sys/unix.Getpid -> syscall.RawSyscall"}, ""},
		{"socket-named funcdata and types", []string{sdkMcp + ".f -> syscall.Socket.arginfo1", sdkMcp + ".f -> type:syscall.Sockaddr"}, ""},
		{"harmless syscall use", []string{sdkMcp + ".f -> syscall.Getpid"}, ""},
		{"harmless dependency", []string{sdkMcp + ".f -> encoding/json.Marshal", "github.com/segmentio/asm/cpu.init -> golang.org/x/sys/cpu.X86"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkLinkReach(testMod, linkGraphOf(t, tt.lines...), map[string]bool{})
			if tt.want == "" {
				if len(got) > 0 {
					t.Errorf("false positive: %v", got)
				}
				return
			}
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tt.want) {
				t.Errorf("got %v, want a problem naming %s", got, tt.want)
			}
		})
	}
}

func TestReviewedEdgesMustStayLinked(t *testing.T) {
	seen := map[string]bool{}
	for edge := range linkReviewed {
		checkLinkReach(testMod, linkGraphOf(t, edge), seen)
	}
	if got := staleReviewed(seen); len(got) > 0 {
		t.Errorf("a reviewed edge in the graph is reported stale: %v", got)
	}
	if got := staleReviewed(map[string]bool{}); len(got) != len(linkReviewed) {
		t.Errorf("unlinked reviewed edges not reported: %v", got)
	}
}

func TestSymbolPackage(t *testing.T) {
	tests := map[string]string{
		"net/http.(*Client).Do":                      "net/http",
		"net.Dial":                                   "net",
		"type:*net/http.Client":                      "net/http",
		sdkMcp + ".(*Server).Run":                    sdkMcp,
		sdkMcp + ".AddTool[go.shape.*uint8,net/x.T]": sdkMcp,
		"go.yaml.in/yaml/v3.(*parser).parse":         "go.yaml.in/yaml/v3",
		"go:string.\"net.Dial\"":                     "",
		"runtime.main":                               "runtime",
		"gclocals·abc":                               "",
	}
	for sym, want := range tests {
		if got := symbolPackage(sym); got != want {
			t.Errorf("symbolPackage(%q) = %q, want %q", sym, got, want)
		}
	}
}

func TestParseLinkGraphFailsClosed(t *testing.T) {
	if _, err := parseLinkGraph(bytes.NewBufferString("# cmd/creep\nlink: warning\n")); err == nil {
		t.Error("a dump with no edges passed")
	}
	g := linkGraphOf(t, "a.f -> b.g <UsedInIface>")
	if len(g["a.f"]) != 1 || g["a.f"][0] != "b.g" {
		t.Errorf("edge parsed as %v", g)
	}
}

// Protection (#32, ADR 0027): creep's code and tests use only the SDK's
// stdio server and test client. Each row is a way to reach a transport
// that could open a socket or start a program.
func TestSDKUsesAllowlisted(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"server and IO transport", `import sdk "` + sdkMcp + `"; var _ = sdk.NewServer; var _ sdk.IOTransport`, ""},
		{"HTTP client transport", `import "` + sdkMcp + `"; var _ mcp.StreamableClientTransport`, sdkMcp + ".StreamableClientTransport"},
		{"HTTP handler", `import m "` + sdkMcp + `"; var _ = m.NewStreamableHTTPHandler`, sdkMcp + ".NewStreamableHTTPHandler"},
		{"SSE", `import "` + sdkMcp + `"; var _ = mcp.NewSSEHandler`, ".NewSSEHandler"},
		{"command transport", `import "` + sdkMcp + `"; var _ = mcp.CommandTransport{}`, ".CommandTransport"},
		{"in-memory transport", `import "` + sdkMcp + `"; var _ = mcp.NewInMemoryTransports`, ".NewInMemoryTransports"},
		{"dot import", `import . "` + sdkMcp + `"; var _ = NewServer`, sdkMcp + ".*"},
		{"blank import", `import _ "` + sdkMcp + `"`, sdkMcp + ".*"},
		{"another SDK package", `import "github.com/modelcontextprotocol/go-sdk/auth"; var _ = auth.RequireBearerToken`, "go-sdk/auth.RequireBearerToken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+tt.src+"\n", parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			got := checkUses("internal/mcp/x.go", sdkUses(file))
			if tt.want == "" {
				if len(got) > 0 {
					t.Errorf("allowed use refused: %v", got)
				}
				return
			}
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tt.want) {
				t.Errorf("got %v, want a problem naming %s", got, tt.want)
			}
		})
	}
}

func TestReleaseTargets(t *testing.T) {
	got, err := releaseTargets("builds:\n  - goos: [linux, windows]\n    goarch: [amd64, arm64]\n")
	if err != nil || len(got) != 4 || got[3] != (target{"windows", "arm64"}) {
		t.Errorf("targets %v, %v", got, err)
	}
	for _, bad := range []string{"", "goos: [linux]\n", "goos: [linux]\ngoarch: [amd64]\n  goos: [darwin]\n"} {
		if _, err := releaseTargets(bad); err == nil {
			t.Errorf("release %q: no error", bad)
		}
	}
}

// The real release config yields the six release targets.
func TestReleaseTargetsOfThisRepo(t *testing.T) {
	data, err := os.ReadFile("../../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := releaseTargets(string(data))
	if err != nil || len(got) != 6 {
		t.Errorf("targets %v, %v; want linux, darwin and windows on amd64 and arm64", got, err)
	}
}

// The module's own sources use only allowed SDK names.
func TestThisRepoUsesOnlyAllowedSDKNames(t *testing.T) {
	problems, err := checkSourceUses("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
