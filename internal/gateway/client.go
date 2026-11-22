package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrRedirect means a response redirected to another scheme, host or port.
var ErrRedirect = errors.New("redirect to another origin refused")

const maxRedirects = 10

// Default timeouts, so a stalled endpoint cannot hang a scan. They are
// constants until they get config keys. The
// response-header wait is long because a non-streaming model answer arrives
// only when generation ends. dialTimeout bounds one DNS lookup and one
// address; dialAllTimeout bounds a dial over every pinned address. A body
// fails after bodyIdleTimeout without a byte or bodyTotalTimeout in all.
const (
	dialTimeout           = 10 * time.Second
	dialAllTimeout        = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 5 * time.Minute
	bodyIdleTimeout       = 2 * time.Minute
	bodyTotalTimeout      = 10 * time.Minute
	idleConnTimeout       = 90 * time.Second
)

// Options configures NewClient. Only Allow is exported: it comes from
// configuration (egress.allow). The resolver, dialer and CA pool stay
// unexported so no caller outside the gateway can map a consented,
// allowlisted name to another address or trust its own CA (#115). Tests in
// this package set them to run without real DNS or network; their zero
// values are the system resolver, dialer and roots.
type Options struct {
	Allow []string

	resolver netResolver
	dial     dialFunc
	rootCAs  *x509.CertPool
	limits   timeLimits // zero fields take the defaults; tests shorten them
}

// Client is the handle Send uses to reach a model. It is opaque on purpose:
// it has no HTTP methods and exposes no *http.Client, so code outside the
// gateway can send a model request only through EgressLog.Send, which checks
// consent and writes egress.log first.
type Client struct {
	hc *http.Client
}

// CloseIdleConnections closes idle keep-alive connections.
func (c *Client) CloseIdleConnections() {
	c.hc.CloseIdleConnections()
}

// NewClient returns the only client creep uses to reach a model; see
// newHTTPClient for what it enforces.
func NewClient(opts Options) (*Client, error) {
	hc, err := newHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	return &Client{hc: hc}, nil
}

// newHTTPClient builds the allowlisted, pinned HTTP client.
//
// Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, ALL_PROXY)
// are ignored: a proxy would receive the hostname and resolve it itself,
// bypassing the allowlist's address checks and IP pinning, and routing
// scanned code through a host the user never listed. Proxy support, if it
// comes, will be an explicit config key that is itself allowlisted.
func newHTTPClient(opts Options) (*http.Client, error) {
	allow, err := parseAllowlist(opts.Allow)
	if err != nil {
		return nil, fmt.Errorf("gateway client: %w", err)
	}
	d := newPinningDialer(allow, opts.resolver, opts.dial, opts.limits)
	return &http.Client{
		Transport:     guard{allow: allow, limits: d.limits, next: newTransport(d, opts.rootCAs)},
		CheckRedirect: sameOrigin,
	}, nil
}

func newTransport(d *pinningDialer, roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          16,
	}
}

// guard checks every request, redirects included, before the transport can
// resolve or dial anything, and bounds the time its response body may take.
type guard struct {
	allow  allowlist
	limits timeLimits
	next   http.RoundTripper
}

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.allow.checkURL(req.URL); err != nil {
		// A RoundTripper must close the request body, even on error.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("gateway: %w", err)
	}
	ctx, cancel := context.WithCancel(req.Context())
	resp, err := g.next.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Request = req
	resp.Body = watchBody(resp.Body, cancel, g.limits)
	return resp, nil
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the
// transport through the guard.
func (g guard) CloseIdleConnections() {
	if c, ok := g.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// sameOrigin allows a redirect only to the same scheme, host and port as the
// first request. A scheme change is refused both ways: https→http is a
// downgrade, and http→https on loopback is never needed.
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("gateway: stopped after %d redirects", maxRedirects)
	}
	from, err := origin(via[0].URL)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	to, err := origin(req.URL)
	if err != nil || to != from {
		return fmt.Errorf("gateway: %q to %q: %w", from, req.URL.Redacted(), ErrRedirect)
	}
	return nil
}

func origin(u *url.URL) (string, error) {
	host, port, err := hostPort(u)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}
