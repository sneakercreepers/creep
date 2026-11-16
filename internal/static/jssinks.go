package static

import "strings"

// jsSinkBase is the SinkAPI of jsSinkSpecs[0], so JavaScript APIs never
// collide with Python ones while either table grows.
const jsSinkBase SinkAPI = 128

// jsSinkSpecs is indexed by SinkAPI - jsSinkBase. Append only: the index is
// the API's identity. Module names are as required or imported, without the
// "node:" scheme; fs/promises, fs.promises and fs-extra read as fs.
var jsSinkSpecs = []sinkSpec{
	// SQL
	{".query", SinkSQL},
	{".execute", SinkSQL},
	{".raw", SinkSQL},
	{".whereRaw", SinkSQL},
	{".$queryRawUnsafe", SinkSQL},
	{".$executeRawUnsafe", SinkSQL},
	// NoSQL (MongoDB driver and Mongoose model methods)
	{".find", SinkNoSQL}, // only with an object literal filter; see jsFindNeedsObject
	{".findOne", SinkNoSQL},
	{".findOneAndUpdate", SinkNoSQL},
	{".findOneAndDelete", SinkNoSQL},
	{".findOneAndReplace", SinkNoSQL},
	{".updateOne", SinkNoSQL},
	{".updateMany", SinkNoSQL},
	{".deleteOne", SinkNoSQL},
	{".deleteMany", SinkNoSQL},
	{".replaceOne", SinkNoSQL},
	{".countDocuments", SinkNoSQL},
	{".aggregate", SinkNoSQL},
	// Shell
	{"child_process.exec", SinkShell},
	{"child_process.execSync", SinkShell},
	{"child_process.execFile", SinkShell},
	{"child_process.execFileSync", SinkShell},
	{"child_process.spawn", SinkShell},
	{"child_process.spawnSync", SinkShell},
	{"child_process.fork", SinkShell},
	// File
	{"fs.readFile", SinkFile},
	{"fs.readFileSync", SinkFile},
	{"fs.writeFile", SinkFile},
	{"fs.writeFileSync", SinkFile},
	{"fs.appendFile", SinkFile},
	{"fs.appendFileSync", SinkFile},
	{"fs.createReadStream", SinkFile},
	{"fs.createWriteStream", SinkFile},
	{"fs.open", SinkFile},
	{"fs.openSync", SinkFile},
	{"fs.unlink", SinkFile},
	{"fs.unlinkSync", SinkFile},
	{"fs.rm", SinkFile},
	{"fs.rmSync", SinkFile},
	{"fs.readdir", SinkFile},
	{"fs.readdirSync", SinkFile},
	{".sendFile", SinkFile},
	{".download", SinkFile},
	// HTTP client
	{"fetch", SinkHTTPClient},
	{"node-fetch", SinkHTTPClient},
	{"axios", SinkHTTPClient},
	{"axios.get", SinkHTTPClient},
	{"axios.post", SinkHTTPClient},
	{"axios.put", SinkHTTPClient},
	{"axios.patch", SinkHTTPClient},
	{"axios.delete", SinkHTTPClient},
	{"axios.head", SinkHTTPClient},
	{"axios.request", SinkHTTPClient},
	{"got", SinkHTTPClient},
	{"got.get", SinkHTTPClient},
	{"got.post", SinkHTTPClient},
	{"http.get", SinkHTTPClient},
	{"http.request", SinkHTTPClient},
	{"https.get", SinkHTTPClient},
	{"https.request", SinkHTTPClient},
	{"undici.request", SinkHTTPClient},
	{"undici.fetch", SinkHTTPClient},
	// Template
	{".render", SinkTemplate},
	{"ejs.render", SinkTemplate},
	{"ejs.compile", SinkTemplate},
	{"pug.render", SinkTemplate},
	{"pug.compile", SinkTemplate},
	{"handlebars.compile", SinkTemplate},
	{"nunjucks.renderString", SinkTemplate},
}

// jsFindNeedsObject: Array.prototype.find shares the name of MongoDB's
// find, so ".find" counts only when its first argument is an object literal
// filter, never a callback.
const jsFindNeedsObject = ".find"

// fsAliases are module prefixes that expose the fs API.
var fsAliases = []string{"fs.promises.", "fs/promises.", "fs-extra."}

// lookupJSSink matches a resolved callee; method is set when the receiver is
// not an import, so only "."-prefixed specs apply.
func lookupJSSink(callee string, method bool) (SinkAPI, bool) {
	if method {
		callee = "." + callee
	}
	for _, alias := range fsAliases {
		if rest, ok := strings.CutPrefix(callee, alias); ok {
			callee = "fs." + rest
		}
	}
	for i, s := range jsSinkSpecs {
		if s.name == callee {
			return jsSinkBase + SinkAPI(i), true //nolint:gosec // G115: the table has far fewer than 128 entries
		}
	}
	return 0, false
}
