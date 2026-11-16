package static

// SinkAPI identifies the matched call in creep's own sink table, for example
// "subprocess.run" or ".execute". Its names come from creep, never from the
// scanned repository, so the planner may see them. Python APIs index
// pySinkSpecs; JavaScript APIs start at jsSinkBase and index jsSinkSpecs.
type SinkAPI uint8

// String returns the table name of the API.
func (a SinkAPI) String() string {
	if s, ok := a.spec(); ok {
		return s.name
	}
	return "unknown"
}

// Kind returns the sink class of the API.
func (a SinkAPI) Kind() SinkKind {
	if s, ok := a.spec(); ok {
		return s.kind
	}
	return 0
}

func (a SinkAPI) spec() (sinkSpec, bool) {
	switch {
	case a >= jsSinkBase && int(a-jsSinkBase) < len(jsSinkSpecs):
		return jsSinkSpecs[a-jsSinkBase], true
	case a > 0 && int(a) < len(pySinkSpecs):
		return pySinkSpecs[a], true
	}
	return sinkSpec{}, false
}

// sinkSpec is one sink. A name starting with "." matches a method call
// on any receiver that is not an imported module; other names match the
// callee's import-resolved dotted name exactly.
type sinkSpec struct {
	name string
	kind SinkKind
}

// pySinkSpecs is indexed by SinkAPI; entry 0 is a placeholder so the zero
// SinkAPI is not a real API. Append only: the index is the API's identity.
var pySinkSpecs = []sinkSpec{
	{"unknown", 0},
	// SQL
	{".execute", SinkSQL},
	{".executemany", SinkSQL},
	{".executescript", SinkSQL},
	{".exec_driver_sql", SinkSQL},
	{".raw", SinkSQL},
	{"sqlalchemy.text", SinkSQL},
	// Shell
	{"os.system", SinkShell},
	{"os.popen", SinkShell},
	{"subprocess.run", SinkShell},
	{"subprocess.call", SinkShell},
	{"subprocess.check_call", SinkShell},
	{"subprocess.check_output", SinkShell},
	{"subprocess.Popen", SinkShell},
	{"subprocess.getoutput", SinkShell},
	{"subprocess.getstatusoutput", SinkShell},
	// File
	{"open", SinkFile},
	{"io.open", SinkFile},
	{"flask.send_file", SinkFile},
	{"flask.send_from_directory", SinkFile},
	{"fastapi.responses.FileResponse", SinkFile},
	{"starlette.responses.FileResponse", SinkFile},
	{"os.remove", SinkFile},
	{"os.unlink", SinkFile},
	{"shutil.copy", SinkFile},
	{"shutil.copyfile", SinkFile},
	{"shutil.move", SinkFile},
	{"shutil.rmtree", SinkFile},
	// HTTP client
	{"requests.get", SinkHTTPClient},
	{"requests.post", SinkHTTPClient},
	{"requests.put", SinkHTTPClient},
	{"requests.patch", SinkHTTPClient},
	{"requests.delete", SinkHTTPClient},
	{"requests.head", SinkHTTPClient},
	{"requests.request", SinkHTTPClient},
	{"httpx.get", SinkHTTPClient},
	{"httpx.post", SinkHTTPClient},
	{"httpx.put", SinkHTTPClient},
	{"httpx.patch", SinkHTTPClient},
	{"httpx.delete", SinkHTTPClient},
	{"httpx.head", SinkHTTPClient},
	{"httpx.request", SinkHTTPClient},
	{"httpx.stream", SinkHTTPClient},
	{"urllib.request.urlopen", SinkHTTPClient},
	// Template
	{"flask.render_template", SinkTemplate},
	{"flask.render_template_string", SinkTemplate},
	{"jinja2.Template", SinkTemplate},
	{"markupsafe.Markup", SinkTemplate},
	{".from_string", SinkTemplate},
	{".TemplateResponse", SinkTemplate},
}

// lookupSink matches a resolved callee. method is set when the receiver is
// not an import, so only "."-prefixed specs apply.
func lookupSink(callee string, method bool) (SinkAPI, bool) {
	if method {
		callee = "." + callee
	}
	for i, s := range pySinkSpecs[1:] {
		if s.name == callee {
			return SinkAPI(i + 1), true //nolint:gosec // G115: the table has far fewer than 256 entries
		}
	}
	return 0, false
}
