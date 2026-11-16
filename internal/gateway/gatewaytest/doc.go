// Package gatewaytest serves a fake model endpoint on loopback for tests outside the gateway.
//
// Tests outside internal/gateway may not import net/http (AGENTS.md
// invariant 1), so a test that drives a whole scan through the real gateway,
// such as the holistic protection test in internal/cli (#17), gets its
// endpoint here. The endpoint counts the connections it accepts and keeps
// every request body, so a test can check what reached the network.
// `make budget` lets only _test.go files import this package, so it never
// ships in the binary.
package gatewaytest
