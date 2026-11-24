package main

import (
	"regexp"
	"slices"
	"strings"
)

// sysPackages hold the raw system-call wrappers. A socket, connect or exec
// there opens a connection or starts a program without net or os/exec, so
// the package list in main.go alone would miss it.
const (
	syscallPkg = "syscall"
	xsysUnix   = "golang.org/x/sys/unix"
	xsysWin    = "golang.org/x/sys/windows"
	xsysModule = "golang.org/x/sys"
)

var sysPackages = []string{syscallPkg, xsysUnix, xsysWin}

// sysPrimitive names the wrappers that open a socket, send on one or start
// a program, on every release OS, with the lower-case internal wrappers
// the exported ones call on Linux and macOS. They are watched on any path; the
// standard library reaches them only through net, os/exec and
// os.StartProcess, which stop the walk first.
var sysPrimitive = regexp.MustCompile(`^(socket|connect|sendto|sendmsg|sendmsgN|sendmmsg|Socket|Connect|ConnectEx|Sendto|Sendmsg|SendmsgN|Sendmmsg|Exec|ForkExec|forkExec|StartProcess|CreateProcess|CreateProcessAsUser|ShellExecute|ShellExecuteEx|WSASocket|WSAConnect|WSASendTo|WSAIoctl)$`)

// rawCall names the entry points that make any system call by number or
// any DLL call by name: a program can open a socket or start a program
// through them without a named wrapper.
var rawCall = regexp.MustCompile(`^((Raw)?Syscall[0-9N]*|\(\*(Lazy)?Proc\)\.Call)$`)

// isSysPrimitive reports a socket or exec wrapper in syscall or x/sys.
func isSysPrimitive(sym string) bool {
	pkg, name, ok := sysSymbol(sym)
	return ok && slices.Contains(sysPackages, pkg) && sysPrimitive.MatchString(name)
}

// isRawSysEdge reports third-party code outside x/sys calling a raw
// system-call entry point, or any function of x/sys/unix or x/sys/windows:
// creep links neither today (x/sys only for cpu), so each new edge must be
// reviewed in linkReviewed. The standard library and x/sys's own wrappers
// make raw calls all the time; only the third-party caller is judged.
func isRawSysEdge(modPath, from, to string) bool {
	fromPkg := symbolPackage(from)
	if !isThirdParty(modPath, fromPkg) || underPath(fromPkg, xsysModule) {
		return false
	}
	pkg, name, ok := sysSymbol(to)
	if !ok {
		return false
	}
	return pkg == xsysUnix || pkg == xsysWin || (pkg == syscallPkg && rawCall.MatchString(name))
}

// sysSymbol splits a function symbol into its package and name; type
// descriptors, funcdata and static data are not functions.
func sysSymbol(sym string) (pkg, name string, ok bool) {
	if strings.HasPrefix(sym, "type:") || strings.HasPrefix(sym, "go:") || isAux(sym) {
		return "", "", false
	}
	pkg = symbolPackage(sym)
	if pkg == "" {
		return "", "", false
	}
	return pkg, strings.TrimPrefix(sym, pkg+"."), true
}
