// Package mcp serves creep's read-only MCP tools (scan of changed files,
// findings, why) over stdio, for an agent that may itself be under prompt
// injection.
//
// The package speaks the protocol and checks every argument; it never
// scans, opens files or starts anything itself. internal/cli hands it a
// Backend whose scan is a pull-request scan with the sandbox, PoCs,
// optional scanners, consent prompts and calibration runs switched off,
// so a tool call can write nothing outside .creep/ and start no container
// (ADR 0027). Only the SDK's stdio framing is used: no HTTP or command
// transport is linked into creep, which `make budget` proves on the
// linked binary.
package mcp
