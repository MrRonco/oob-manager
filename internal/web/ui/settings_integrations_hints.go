package ui

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// hintsView holds the copy-ready snippets for pull-style integrations. They embed this
// instance's URL and a <token> placeholder, never a real token.
type hintsView struct {
	BaseURL        string
	Homepage       string
	Kuma           string
	KumaMetrics    string
	Prometheus     string
	MetricsOn      bool
	MetricsAllowed string // metrics.allow_networks, "any address" when empty
}

// tokenPlaceholder stands for a read-only API token in every snippet.
const tokenPlaceholder = "<token>"

func (s *server) hintsFor(r *http.Request) hintsView {
	base := strings.TrimSuffix(s.d.PublicURL, "/")
	if base == "" {
		base = "https://" + r.Host
	}
	host := base
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		host = u.Host
	}
	id := "<server id>"
	if views := s.d.Fleet.Servers(); len(views) > 0 {
		id = views[0].ID
	}
	v := hintsView{BaseURL: base, MetricsOn: s.d.Hints.MetricsEnabled, MetricsAllowed: "any address (a token is still required)"}
	if len(s.d.Hints.MetricsNetworks) > 0 {
		v.MetricsAllowed = strings.Join(s.d.Hints.MetricsNetworks, ", ")
	}
	v.Homepage = homepageSnippet(base, id)
	v.Kuma = "Monitor type: HTTP(s) - Keyword\nURL:          " + base + "/readyz\nKeyword:      ok\n" +
		"Certificate:  trust this console's certificate (gen-tls) or its CA on the Kuma host\n" +
		"No token: /readyz answers ok, degraded or unavailable and nothing else."
	v.KumaMetrics = "Monitor type: HTTP(s) - Keyword\nURL:          " + base + "/metrics\n" +
		"Headers:      {\"Authorization\": \"Bearer " + tokenPlaceholder + "\"}\nKeyword:      oob_server_up{server=\"" + id + "\"} 1"
	v.Prometheus = prometheusSnippet(host)
	return v
}

func homepageSnippet(base, id string) string {
	return "- Out-of-band console:\n" +
		"    href: " + base + "/servers/" + id + "\n" +
		"    widget:\n" +
		"      type: customapi\n" +
		"      url: " + base + "/api/v1/servers/" + id + "\n" +
		"      headers:\n" +
		"        Authorization: Bearer " + tokenPlaceholder + "\n" +
		"      mappings:\n" +
		"        - field: health\n" +
		"          label: Health\n" +
		"        - field: power_state\n" +
		"          label: Power\n" +
		"        - field: stale\n" +
		"          label: Stale"
}

func prometheusSnippet(host string) string {
	return "scrape_configs:\n" +
		"  - job_name: oob-manager\n" +
		"    scheme: https\n" +
		"    scrape_interval: 30s\n" +
		"    metrics_path: /metrics\n" +
		"    authorization:\n" +
		"      type: Bearer\n" +
		"      credentials_file: /etc/prometheus/oob-manager.token   # holds " + tokenPlaceholder + "\n" +
		"    tls_config:\n" +
		"      ca_file: /etc/prometheus/oob-manager.crt             # this console's certificate or its CA\n" +
		"    static_configs:\n" +
		"      - targets: [\"" + host + "\"]"
}

// prefixList renders networks for the page ("10.0.0.0/8, 192.168.0.0/16").
func prefixList(ps []netip.Prefix) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	if len(out) == 0 {
		return "none (shipping cannot be enabled)"
	}
	return strings.Join(out, ", ")
}
