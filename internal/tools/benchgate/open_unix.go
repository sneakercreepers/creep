//go:build unix

package main

import "syscall"

// nonblockFlag makes opening a FIFO named as an input return at once
// instead of hanging the gate; it is a no-op on regular files.
const nonblockFlag = syscall.O_NONBLOCK
