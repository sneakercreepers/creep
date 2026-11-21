package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// ErrNoConsent means the endpoint has no consent: the user declined, could
// not be asked, or (in CI) the policy does not list it.
var ErrNoConsent = errors.New("no consent to send code to this endpoint")

// errPromptTimeout means nobody answered the consent prompt in time; the
// endpoint is refused like a decline.
var errPromptTimeout = errors.New("no answer to the consent prompt")

// promptTimeout bounds one consent prompt.
const promptTimeout = 5 * time.Minute

// ConsentError is returned by Send when consent is missing or cannot be
// determined (an unreadable or unsafe consent store, Err). Both fail closed
// the same way: nothing is sent and ExitCode is exitcode.ConfigError (2),
// because the fix is in configuration, not in the model.
type ConsentError struct {
	Endpoint string // normalized origin, e.g. "https://api.example.com:443"
	CI       bool
	Err      error // why consent could not be read; nil for a plain refusal
}

func (e *ConsentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v: %v; nothing was sent", e.Endpoint, ErrNoConsent, e.Err)
	}
	if e.CI {
		return fmt.Sprintf("%s: %v; in CI consent comes only from the policy file (CREEP_POLICY, key consent)", e.Endpoint, ErrNoConsent)
	}
	return fmt.Sprintf("%s: %v; nothing was sent", e.Endpoint, ErrNoConsent)
}

func (e *ConsentError) Unwrap() []error { return []error{ErrNoConsent, e.Err} }

// ExitCode is the process exit code for a run stopped by missing consent.
func (e *ConsentError) ExitCode() int { return exitcode.ConfigError }

// Prompt asks the user whether redacted code may be sent to endpoint (a
// normalized origin). Anything but an explicit yes is a decline; an error
// is a decline too, and so is no answer within five minutes (Send then
// returns a *ConsentError that says so).
type Prompt func(endpoint string) (bool, error)

// ConsentOptions configures NewConsent.
type ConsentOptions struct {
	CI        bool     // from config.InCI: never prompt, consult only Policy
	Policy    []string // config.Resolved.PolicyConsent()
	StorePath string   // local consent file; "" keeps answers for this run only
	Prompt    Prompt   // nil declines every endpoint not already consented
}

// Consent decides, per endpoint origin (scheme, host and effective port,
// normalized as the egress.allow check does), whether Send may proceed.
//
// In CI only the policy grants consent and nothing prompts. Locally the
// policy, then the stored answers, then the prompt; a yes is stored so each
// endpoint is asked once, a no is remembered for this run only, so a later
// run asks again.
//
// The zero value refuses every endpoint: no policy, no store, no prompt.
type Consent struct {
	mu         sync.Mutex
	ci         bool
	policy     map[string]bool
	store      string
	prompt     Prompt
	promptWait time.Duration   // zero is promptTimeout; tests shorten it
	session    map[string]bool // answers given during this run
}

// NewConsent validates the policy entries. Each is an origin URL such as
// "https://api.example.com" or "https://10.0.0.5:8443", with no path,
// userinfo, query or fragment, or a command endpoint such as
// "command://claude-0123456789abcdef" (creep doctor prints it). A
// StorePath must be absolute: a relative one would resolve in the working
// directory, which is the scanned repository (#116).
func NewConsent(opts ConsentOptions) (*Consent, error) {
	if opts.StorePath != "" && !filepath.IsAbs(opts.StorePath) {
		return nil, fmt.Errorf("consent store %q: not an absolute path: %w", opts.StorePath, ErrUnsafeConsentStore)
	}
	c := &Consent{
		ci:      opts.CI,
		policy:  map[string]bool{},
		store:   opts.StorePath,
		prompt:  opts.Prompt,
		session: map[string]bool{},
	}
	for _, s := range opts.Policy {
		key, err := parsePolicyEntry(s)
		if err != nil {
			return nil, err
		}
		c.policy[key] = true
	}
	return c, nil
}

// CheckPolicyConsent validates policy consent entries as NewConsent does,
// so the CLI can refuse a bad entry when it loads the configuration, for
// every command, instead of at the first model call (#116).
func CheckPolicyConsent(entries []string) error {
	for _, s := range entries {
		if _, err := parsePolicyEntry(s); err != nil {
			return err
		}
	}
	return nil
}

func parsePolicyEntry(s string) (string, error) {
	key, err := parseOrigin(s)
	if err != nil {
		return "", fmt.Errorf("policy consent entry %q: %w", s, err)
	}
	return key, nil
}

// check returns nil when endpoint may receive a request, and a
// *ConsentError otherwise. It holds the lock while prompting, so concurrent
// calls to one endpoint ask once.
func (c *Consent) check(endpoint *url.URL) error {
	key, err := origin(endpoint)
	if err != nil {
		return &ConsentError{Endpoint: "(invalid endpoint)", CI: c.ci, Err: err}
	}
	return c.checkKey(key)
}

// checkKey is check for a normalized origin or a command endpoint.
func (c *Consent) checkKey(key string) error {
	if c.policy[key] {
		return nil
	}
	if c.ci {
		return &ConsentError{Endpoint: key, CI: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ok, err := c.local(key)
	if err != nil {
		return &ConsentError{Endpoint: key, Err: err}
	}
	if !ok {
		return &ConsentError{Endpoint: key}
	}
	return nil
}

// local consults this run's answers, the store, then the prompt. The
// session map is made here, not only in NewConsent, so a zero-value
// Consent refuses like one with no prompt instead of panicking (#115).
func (c *Consent) local(key string) (bool, error) {
	if c.session == nil {
		c.session = map[string]bool{}
	}
	if ok, asked := c.session[key]; asked {
		return ok, nil
	}
	stored, err := c.stored(key)
	if err != nil || stored {
		return stored, err
	}
	ok, err := c.ask(key)
	c.session[key] = ok
	if err != nil {
		return false, err
	}
	if !ok || c.store == "" {
		return ok, nil
	}
	// Failing to store a yes refuses the call: the user was told the answer
	// is kept, and a silent failure would ask again on every run.
	if err := addStoredConsent(c.store, key); err != nil {
		delete(c.session, key)
		return false, err
	}
	return true, nil
}

func (c *Consent) stored(key string) (bool, error) {
	if c.store == "" {
		return false, nil
	}
	keys, err := readConsentStore(c.store)
	if err != nil {
		return false, err
	}
	return keys[key], nil
}

// ask runs the prompt with a deadline. In a CI run InCI missed that still
// has a terminal nobody answers, and the prompt holds the consent lock, so
// without one every call would wait forever (#116). On timeout the prompt's
// goroutine is left blocked on its read; a late answer is dropped, and a
// line it consumes can only make a later prompt decline.
func (c *Consent) ask(key string) (bool, error) {
	if c.prompt == nil {
		return false, nil
	}
	wait := c.promptWait
	if wait <= 0 {
		wait = promptTimeout
	}
	answer := make(chan bool, 1)
	go func() {
		ok, err := c.prompt(key)
		answer <- err == nil && ok
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ok := <-answer:
		return ok, nil
	case <-timer.C:
		return false, fmt.Errorf("%w in %v", errPromptTimeout, wait)
	}
}

// parseOrigin accepts scheme://host[:port] with an optional trailing "/"
// and returns it normalized like the allowlist: lowercase host, canonical
// IP, explicit port. A command endpoint (Command.Endpoint) is kept as is.
func parseOrigin(s string) (string, error) {
	if isCommandKey(s) {
		return s, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%w: not a URL", ErrInvalidHost)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme %q: want http or https", u.Scheme)
	}
	bare := u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
	if !bare {
		return "", errors.New("want scheme://host[:port] with no path, userinfo, query or fragment")
	}
	return origin(u)
}
