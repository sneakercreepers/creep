package static

import "strings"

// knownPackages are packages whose sink-named methods are not database
// calls: utility and view libraries (ReactDOM.render, _.find, R.find),
// graphql's execute, express and express-validator's query().
// Packages of the sink table are known too (see jsKnownPackage).
var knownPackages = map[string]bool{
	"express": true, "react": true, "react-dom": true,
	"lodash": true, "lodash-es": true, "underscore": true, "fs-extra": true,
	"ramda": true, "graphql": true, "express-validator": true,
}

// unseenAliasCall reports a call to a sink-named method (.query, .find,
// .findOne, ...) on an import whose specifier is neither relative nor a
// known package. It may be a tsconfig or bundler path alias (src/db,
// @app/models) for a module of the repository, which static analysis does
// not resolve, so the route is marked partial instead of silently empty.
func (f *jsFile) unseenAliasCall(callee *Node) bool {
	spec, method, ok := f.importedCall(callee)
	if !ok || localModule(spec) || jsKnownPackage(packageRoot(spec)) {
		return false
	}
	_, sinkNamed := lookupJSSink(method, true)
	return sinkNamed
}

// importedCall splits a callee on an import into its specifier (with
// .member for a named import) and the called method: the outermost
// property, or for a bare named import its member name.
func (f *jsFile) importedCall(n *Node) (spec, method string, ok bool) {
	var props []string
	for n != nil && n.Type == "member_expression" {
		props = append(props, f.text(field(n, "property")))
		n = field(n, "object")
	}
	spec, ok = f.requireCall(n)
	if !ok && n != nil && n.Type == "identifier" {
		spec, ok = f.imports[f.text(n)]
	}
	if !ok {
		return "", "", false
	}
	if len(props) > 0 {
		return spec, props[0], true
	}
	return spec, namedMember(spec), true
}

// namedMember returns the member of "module.member", "" when there is none.
func namedMember(spec string) string {
	slash := strings.LastIndex(spec, "/")
	dot := strings.LastIndex(spec, ".")
	if dot <= slash {
		return ""
	}
	return spec[dot+1:]
}

// packageRoot returns the package name of a specifier: "@scope/name" or
// "name", without a subpath or a .member.
func packageRoot(spec string) string {
	parts := strings.SplitN(spec, "/", 3)
	root := parts[0]
	if strings.HasPrefix(root, "@") && len(parts) > 1 {
		root += "/" + parts[1]
	}
	if i := strings.Index(root, "."); i > 0 {
		root = root[:i]
	}
	return root
}

// jsKnownPackage reports a package of knownPackages or of the sink table.
func jsKnownPackage(root string) bool {
	if knownPackages[root] {
		return true
	}
	for _, s := range jsSinkSpecs {
		if !strings.HasPrefix(s.name, ".") && packageRoot(s.name) == root {
			return true
		}
	}
	return false
}
