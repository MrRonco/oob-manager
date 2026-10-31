package ui

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

var linkifyTmpl = template.Must(template.New("n").Parse(
	`{{range .}}{{if .Href}}<a href="{{.Href}}" rel="noopener noreferrer">{{.Text}}</a>{{else}}{{.Text}}{{end}}{{end}}`))

// FuzzLinkify: segments re-join to the input, links are http(s) only, and the rendered
// HTML never carries an unescaped "<" from the note or a javascript: href.
func FuzzLinkify(f *testing.F) {
	for _, s := range []string{"see https://192.0.2.10/x.", "javascript:alert(1) http://a/<b>", "http://\"onmouseover=x", "a\nb https://x.y/?q=1&r=<2>)", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		segs := linkify(body)
		var joined strings.Builder
		for _, s := range segs {
			joined.WriteString(s.Text)
			if s.Href != "" && !strings.HasPrefix(s.Href, "http://") && !strings.HasPrefix(s.Href, "https://") {
				t.Fatalf("non-http link %q", s.Href)
			}
		}
		if joined.String() != body {
			t.Fatalf("segments dropped text: %q -> %q", body, joined.String())
		}
		var out bytes.Buffer
		if err := linkifyTmpl.Execute(&out, segs); err != nil {
			t.Fatal(err)
		}
		html := out.String()
		if strings.Contains(strings.ToLower(html), "href=\"javascript:") {
			t.Fatalf("javascript href in %q", html)
		}
		stripped := strings.NewReplacer(`<a href="`, "", `" rel="noopener noreferrer">`, "", "</a>", "").Replace(html)
		if strings.Contains(stripped, "<") {
			t.Fatalf("unescaped < in %q", html)
		}
	})
}
