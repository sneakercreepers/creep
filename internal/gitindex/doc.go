// Package gitindex reads the paths a git index tracks.
//
// creep lists an installed dependency tree as vendor only when git tracks
// nothing in it (ADR 0009 amendment, #213), so it must know what the
// scanned repository commits without running git. The index is repository
// bytes, so Parse treats it as hostile: the checksum is verified first and
// picks the hash length (SHA-1 or SHA-256), versions 2 to 4 are read whole
// or refused, an extension git requires readers to understand (split or
// sparse index) is refused, and paths are capped (MaxPathBytes,
// MaxPathTotal) so a prefix-compressed version 4 index cannot expand.
// Callers read at most MaxBytes. Any error means "not known", and the
// caller must then treat every vendor tree as unproven.
package gitindex
