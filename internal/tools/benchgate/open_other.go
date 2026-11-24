//go:build !unix

package main

// nonblockFlag is empty: Windows has no FIFOs that block on open, and the
// regular-file check refuses devices.
const nonblockFlag = 0
