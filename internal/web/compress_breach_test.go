package web

import (
	"net/http"
	"testing"
)

// BREACH (R5): HTML that answers a GET with a query string can reflect it next to a CSRF
// token, so it is sent uncompressed. HTML without a query and static assets with one are
// still compressed.
func TestCompressSkipsHTMLThatMayReflectAQuery(t *testing.T) {
	html := Compress()(textHandler("text/html; charset=utf-8", 4000))
	for _, target := range []string{"https://oob.test/events?q=secret", "https://oob.test/stepup?next=%2Fsettings"} {
		if r := serve(t, html, http.MethodGet, target, "Accept-Encoding", "gzip"); encoding(r) != "" || r.Header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("%s: %v", target, r.Header)
		}
	}
	if r := serve(t, html, http.MethodGet, "https://oob.test/events", "Accept-Encoding", "gzip"); encoding(r) != "gzip" {
		t.Error("HTML without a query was not compressed")
	}
	css := Compress()(textHandler("text/css", 4000))
	if r := serve(t, css, http.MethodGet, "https://oob.test/static/app.css?v=1", "Accept-Encoding", "gzip"); encoding(r) != "gzip" {
		t.Error("a stylesheet with a query was not compressed")
	}
	js := Compress()(textHandler("application/json", 4000))
	if r := serve(t, js, http.MethodGet, "https://oob.test/api/v1/servers?x=1", "Accept-Encoding", "gzip"); encoding(r) != "gzip" {
		t.Error("JSON with a query was not compressed")
	}
}

// htmlWithStatus answers with a large HTML body and the given status.
func htmlWithStatus(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(make([]byte, 4000))
	})
}

// BREACH (review N1): an error page can echo the request path next to the layout's CSRF
// tokens (a 404 for an unknown URL), and a POST answer can hold a one-time secret; only
// a successful answer to a GET without a query string is compressed as HTML.
func TestCompressSkipsErrorPagesAndPostAnswers(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		if r := serve(t, Compress()(htmlWithStatus(status)), http.MethodGet, "https://oob.test/ZZZ", "Accept-Encoding", "gzip"); encoding(r) != "" {
			t.Errorf("a %d page was compressed", status)
		}
	}
	if r := serve(t, Compress()(htmlWithStatus(http.StatusOK)), http.MethodPost, "https://oob.test/enroll/reveal", "Accept-Encoding", "gzip"); encoding(r) != "" {
		t.Error("an HTML answer to a POST was compressed")
	}
	if r := serve(t, Compress()(htmlWithStatus(http.StatusOK)), http.MethodGet, "https://oob.test/servers", "Accept-Encoding", "gzip"); encoding(r) != "gzip" {
		t.Error("a plain GET page was not compressed")
	}
}
