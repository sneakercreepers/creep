package static

import (
	"bytes"
	"fmt"
	"strings"
)

// declarationSuffixes name TypeScript declaration files, compared without
// case.
var declarationSuffixes = []string{".d.ts", ".d.mts", ".d.cts"}

// IsDeclaration reports whether name is a TypeScript declaration file.
func IsDeclaration(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range declarationSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// AddDeclaration is AddJavaScript for a declaration file of a proven
// dependency tree (VendorEvidence). The pinned grammar lags TypeScript's
// type syntax (router 2.x's route.d.ts does not parse, #255 tester M3), so
// a declaration file whose parse has errors is still listed as vendor when
// its code, comments aside, fails MayHoldRoute. When it passes, the file is
// a syntax error like first-party code (#262): a route in a region the
// grammar could not read never hides behind a mark. The file is parsed and
// extracted either way, so a route found is evaluated. Any other file is
// refused.
func (e *Extractor) AddDeclaration(path string, tree *Tree, src []byte) error {
	if !IsDeclaration(path) {
		return fmt.Errorf("extract %s: not a declaration file", path)
	}
	if tree == nil || tree.Root == nil || int(tree.Root.EndByte) > len(src) {
		return e.addSource(path, tree, src, extractJavaScript, false)
	}
	if tree.Language != TypeScript {
		return fmt.Errorf("extract %s: %s tree is not typescript", path, tree.Language)
	}
	lenient := tree.HasError && !MayHoldRoute(TypeScript, withoutComments(tree.Root, src))
	return e.addSource(path, tree, src, extractJavaScript, lenient)
}

// withoutComments returns a copy of src with every comment the parser read
// outside an error region turned into line breaks. A line break only ends
// words and pieces, so the copy errs toward MayHoldRoute true. A comment is
// masked only when its own bytes prove it is one: "//" with no line
// terminator inside, or "/*" closed by its first "*/". So a grammar that
// ends a comment later than JavaScript does (#255 tester M2) masks code.
func withoutComments(root *Node, src []byte) []byte {
	out := bytes.Clone(src)
	stack := []*Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Error || n.Missing {
			continue
		}
		if n.Type == "comment" && plainComment(src[n.StartByte:n.EndByte]) {
			fillLineBreaks(out[n.StartByte:n.EndByte])
			continue
		}
		stack = append(stack, n.Children...)
	}
	return out
}

// plainComment reports whether text is one whole comment and nothing more.
func plainComment(text []byte) bool {
	switch {
	case bytes.HasPrefix(text, []byte("//")):
		return !bytes.ContainsAny(text, "\r\n"+lineSeparator+paragraphSeparator)
	case bytes.HasPrefix(text, []byte("/*")) && len(text) >= 4:
		return bytes.Index(text[2:], []byte("*/")) == len(text)-4
	}
	return false
}

func fillLineBreaks(b []byte) {
	for i := range b {
		b[i] = '\n'
	}
}
