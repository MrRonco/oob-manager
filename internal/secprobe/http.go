package secprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"oob-manager/internal/bmc"
)

// HTTP probe constants.
const (
	wsmanPath = "/wsman"
	// controlPath is a path no BMC serves: when /wsman answers like it, the answer says
	// nothing about WS-Management (for example a server that wants a login everywhere).
	controlPath    = "/oob-manager-absent"
	maxHeaderBytes = 16 << 10
	maxBodyBytes   = 4 << 10
)

var errMethod = errors.New("secprobe: only HEAD and GET are sent")

// readOnlyTransport refuses every method but HEAD and GET before a byte is sent.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		return nil, errMethod
	}
	return t.next.RoundTrip(r)
}

// client dials only addr (whatever the URL says), with no proxy, no keep-alive, no
// redirects, capped headers and the probe bounds.
func client(addr netip.AddrPort, tlsCfg *tls.Config, o Options) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return o.dial(ctx, addr)
		},
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    o.HandshakeTimeout,
		ResponseHeaderTimeout:  o.HandshakeTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: readOnlyTransport{next: tr},
		Timeout:   o.DialTimeout + 2*o.HandshakeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// request sends one request without credentials and returns the status and Location;
// the body is read up to a small cap and dropped.
func request(ctx context.Context, c *http.Client, method, target string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

// CheckHTTP asks the plain-HTTP port for "/" (HEAD, or GET when HEAD is refused) and
// reports whether it redirects to HTTPS. A connection refused (Refused) means the port
// is closed; any other failure says nothing about it.
func CheckHTTP(ctx context.Context, addr netip.AddrPort, o Options) bmc.HTTPProbe {
	o = o.withDefaults()
	p := bmc.HTTPProbe{Port: int(addr.Port())}
	c := client(addr, nil, o)
	target := "http://" + addr.String() + "/"
	status, loc, err := request(ctx, c, http.MethodHead, target)
	if err == nil && (status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented) {
		status, loc, err = request(ctx, c, http.MethodGet, target)
	}
	if err != nil {
		p.Read, p.Refused = failed(err), connRefused(err)
		return p
	}
	p.Read, p.Status = bmc.SectionOf(nil), status
	p.Redirect = status >= 300 && status < 400 && loc != ""
	if p.Redirect {
		u, perr := url.Parse(loc)
		p.ToHTTPS = perr == nil && strings.EqualFold(u.Scheme, "https")
	}
	return p
}

// CheckWSMan sends HEAD /wsman and HEAD of a control path over the pinned TLS connection,
// without credentials. A host whose key does not match the pin gets no request at all.
func CheckWSMan(ctx context.Context, addr netip.AddrPort, pin []byte, o Options) bmc.WSManProbe {
	o = o.withDefaults()
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // G402: replaced by the SPKI pin check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !pinMatches(cs.PeerCertificates[0], pin) {
				return bmc.ErrPinMismatch
			}
			return nil
		},
	}
	c := client(addr, cfg, o)
	base := "https://" + addr.String()
	status, _, err := request(ctx, c, http.MethodHead, base+wsmanPath)
	if err != nil {
		return bmc.WSManProbe{Read: failed(err)}
	}
	control, _, err := request(ctx, c, http.MethodHead, base+controlPath)
	if err != nil {
		return bmc.WSManProbe{Read: failed(err)}
	}
	return bmc.WSManProbe{Read: bmc.SectionOf(nil), Status: status, ControlStatus: control}
}
