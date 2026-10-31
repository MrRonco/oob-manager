package fwcatalog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"oob-manager/internal/egress"
	"oob-manager/internal/firmware/catalog"
)

// Fetch bounds (plan 08 §6.3).
const (
	fetchTotal      = 120 * time.Second
	fetchConnect    = 10 * time.Second
	fetchIdle       = 30 * time.Second
	maxSigBytes     = 4 << 10
	fetchSigTimeout = 30 * time.Second
)

// Fetcher downloads one catalog and its detached signature. The URL is fixed at
// construction (from config.yaml, never a request), so nothing can steer it to a
// firmware package or another host.
type Fetcher struct {
	URL       string // https; the signature is URL + ".sign"
	Policy    egress.Policy
	UserAgent string
	// TLS (nil: system roots) and Dial (nil: net.Dialer) are test hooks.
	TLS  *tls.Config
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Idle (0: 30 s) aborts a body that stops arriving; a test hook.
	Idle time.Duration
}

// Fetched is a downloaded catalog: a staged file (see Importer) and its signature, or
// NotModified.
type Fetched struct {
	NotModified        bool
	File               string
	Sig                []byte
	ETag, LastModified string
}

// Fetch downloads the catalog into a staged file under dir, conditionally on etag and
// lastModified. Errors are catalog.ErrDownload, ErrSize or ErrSignature.
func (f Fetcher) Fetch(ctx context.Context, dir, etag, lastModified string) (Fetched, error) {
	if u, err := url.Parse(f.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return Fetched{}, fmt.Errorf("%w: the catalog URL must be https", catalog.ErrDownload)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTotal)
	defer cancel()
	resp, err := f.get(ctx, f.URL, etag, lastModified)
	if err != nil {
		return Fetched{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return Fetched{NotModified: true, ETag: etag, LastModified: lastModified}, nil
	}
	if err = statusError(resp.StatusCode); err != nil {
		return Fetched{}, err
	}
	if resp.ContentLength > MaxCatalogBytes {
		return Fetched{}, fmt.Errorf("%w: the server announced %d bytes", catalog.ErrSize, resp.ContentLength)
	}
	body := f.idle(cancel, resp.Body)
	file, err := Stage(dir, body)
	body.timer.Stop()
	if err != nil {
		return Fetched{}, downloadErr(err)
	}
	sig, err := f.signature(ctx)
	if err != nil {
		_ = os.Remove(file)
		return Fetched{}, err
	}
	return Fetched{File: file, Sig: sig, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, nil
}

func (f Fetcher) get(ctx context.Context, url, etag, lastModified string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: bad URL", catalog.ErrDownload)
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	cl := egress.NewClient(egress.ClientConfig{Dialer: egress.Dialer{Policy: f.Policy, Dial: f.dial()}, TLS: f.TLS,
		HeaderTimeout: fetchConnect})
	defer cl.CloseIdleConnections()
	resp, err := cl.Do(req) //nolint:gosec // G704: the URL is file-only (https) and the dialer enforces the egress policy
	if err != nil {
		return nil, downloadErr(err)
	}
	return resp, nil
}

func (f Fetcher) dial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if f.Dial != nil {
		return f.Dial
	}
	return (&net.Dialer{Timeout: fetchConnect}).DialContext
}

// signature downloads URL.sign (at most 4 KiB). A missing file is ErrSignature.
func (f Fetcher) signature(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchSigTimeout)
	defer cancel()
	resp, err := f.get(ctx, f.URL+".sign", "", "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: the signature file answered %d", catalog.ErrSignature, resp.StatusCode)
	}
	sig, err := io.ReadAll(io.LimitReader(resp.Body, maxSigBytes+1))
	if err != nil {
		return nil, downloadErr(err)
	}
	if len(sig) > maxSigBytes {
		return nil, fmt.Errorf("%w: the signature file is larger than %d bytes", catalog.ErrSignature, maxSigBytes)
	}
	return sig, nil
}

func statusError(code int) error {
	switch {
	case code == http.StatusOK:
		return nil
	case code >= 300 && code < 400:
		return fmt.Errorf("%w: the server redirected (%d); redirects are not followed, set firmware.catalog.url to the final URL",
			catalog.ErrDownload, code)
	default:
		return fmt.Errorf("%w: the server answered %d", catalog.ErrDownload, code)
	}
}

// downloadErr classifies a transport error: a policy refusal keeps its reason (it names
// the rule, never an address), anything else is a short class. ErrSize passes through.
func downloadErr(err error) error {
	var dns *egress.DNSError
	var cv *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.Is(err, catalog.ErrSize):
		return err
	case errors.Is(err, egress.ErrBlocked):
		return fmt.Errorf("%w: %w", catalog.ErrDownload, err)
	case errors.As(err, &dns):
		return fmt.Errorf("%w: the host name did not resolve", catalog.ErrDownload)
	case errors.As(err, &cv):
		return fmt.Errorf("%w: TLS certificate not trusted", catalog.ErrDownload)
	case errors.Is(err, errStalled):
		return fmt.Errorf("%w: the download stalled", catalog.ErrDownload)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return fmt.Errorf("%w: timed out", catalog.ErrDownload)
	default:
		return fmt.Errorf("%w: network error", catalog.ErrDownload)
	}
}

var errStalled = errors.New("fwcatalog: no data for too long")

// idle wraps body so that no byte for the idle period cancels the request.
func (f Fetcher) idle(cancel context.CancelFunc, body io.Reader) *idleReader {
	d := f.Idle
	if d <= 0 {
		d = fetchIdle
	}
	r := &idleReader{r: body}
	r.timer = time.AfterFunc(d, func() {
		r.mu.Lock()
		r.stalled = true
		r.mu.Unlock()
		cancel()
	})
	r.d = d
	return r
}

type idleReader struct {
	r       io.Reader
	timer   *time.Timer
	d       time.Duration
	mu      sync.Mutex
	stalled bool
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.timer.Reset(r.d)
	}
	if errors.Is(err, io.EOF) {
		r.timer.Stop()
	}
	r.mu.Lock()
	stalled := r.stalled
	r.mu.Unlock()
	if err != nil && stalled {
		return n, errStalled
	}
	return n, err
}
