package verify

// Template IDs: the only PoCs creep runs.
const (
	TemplateHTTPRequest  = "http_request"
	TemplateHTTPSequence = "http_sequence"
	TemplateSQLPayload   = "sql_payload"
	TemplatePathPayload  = "path_payload"
)

// Placeholders the model writes where creep puts a value of its own.
const (
	// NoncePlaceholder becomes the PoC's fresh nonce, which a reflect
	// oracle looks for in the response.
	NoncePlaceholder = "__CREEP_NONCE__"
	// PayloadPlaceholder becomes creep's payload (sql_payload,
	// path_payload) or, in the baseline request, a harmless value.
	PayloadPlaceholder = "__CREEP_PAYLOAD__"
)

// Oracle kinds of http_request and http_sequence.
const (
	OracleStatus  = "status"  // the response has the expected status
	OracleReflect = "reflect" // the response body holds the nonce
)

// Request is the model's PoC: a template ID and exactly that template's
// parameters. It is a closed struct for models.Complete, which refuses
// unknown, duplicate and case-variant keys, then runs Validate.
type Request struct {
	Template     string        `json:"template"`
	HTTPRequest  *HTTPRequest  `json:"http_request"`
	HTTPSequence *HTTPSequence `json:"http_sequence"`
	SQLPayload   *SQLPayload   `json:"sql_payload"`
	PathPayload  *PathPayload  `json:"path_payload"`
}

// Call is one HTTP request to the app. There is no host, scheme or port:
// the app and its port are fixed by the sandbox and the caller.
type Call struct {
	Method      string   `json:"method"`       // GET, POST, PUT, PATCH, DELETE
	Path        string   `json:"path"`         // origin form: "/" then path and query
	Headers     []Header `json:"headers"`      // names from a closed list
	ContentType string   `json:"content_type"` // "", or json, form or text
	Body        string   `json:"body"`         // only with a content type
}

// Header is one request header the model may set.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Oracle is what makes an http_request or http_sequence verified.
type Oracle struct {
	Kind   string `json:"kind"`   // status or reflect
	Status int    `json:"status"` // the expected status with status; 0 with reflect
}

// HTTPRequest sends one request and judges its response.
type HTTPRequest struct {
	Request Call   `json:"request"`
	Oracle  Oracle `json:"oracle"`
}

// HTTPSequence authenticates, then sends the request with the session the
// auth response gave: its cookies, or a bearer token from one top-level
// string field of its JSON body.
type HTTPSequence struct {
	Auth       Call   `json:"auth"`
	Session    string `json:"session"`     // cookie or bearer
	TokenField string `json:"token_field"` // bearer only
	Request    Call   `json:"request"`
	Oracle     Oracle `json:"oracle"`
}

// SQLPayload puts creep's SQL at the payload placeholder of one request.
// The run's database is PostgreSQL, so the payloads are.
type SQLPayload struct {
	Request   Call   `json:"request"`
	Context   string `json:"context"`   // string (inside quotes) or numeric
	Technique string `json:"technique"` // delay (pg_sleep) or marker (an empty table)
}

// PathPayload puts a path to /etc/passwd at the payload placeholder of one
// request.
type PathPayload struct {
	Request Call   `json:"request"`
	Style   string `json:"style"` // relative, encoded or absolute
	Depth   int    `json:"depth"` // how many ../ (relative, encoded); 0 with absolute
}
