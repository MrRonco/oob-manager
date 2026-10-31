package ui

import (
	"bytes"
	"embed"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

// iconFS holds the vendored Lucide sources. They are read only to build the sprite and
// are not served: static/ (staticHandler) carries just the licence for the About page.
//
//go:embed iconsrc
var iconFS embed.FS

// The icon sprite (round-2 redesign slice B, docs/tech_doc.md §40): one inline
// <svg class="sprite"> per page with a <symbol> per icon, so the "icon" partial only
// writes <use href="#i-name">. Same-document <use> needs no fetch and raises no CSP
// question. The symbols are built once at startup from the vendored Lucide release files
// (unmodified, SHA-256 in vendor.sha256) and the project's own mark (static/mark.svg).
// Every file is parsed and re-serialised through an allow-list of shape elements and
// geometry attributes, so a changed file can never put markup other than shapes into
// every page.

const (
	lucideIconDir = "iconsrc/lucide-1.53.0/icons"
	markFile      = "static/mark.svg"
	markName      = "mark"
)

var iconNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// shapeAttrs are the attributes a symbol child may keep, per element.
var shapeAttrs = map[string][]string{
	"path":     {"d"},
	"circle":   {"cx", "cy", "r"},
	"ellipse":  {"cx", "cy", "rx", "ry"},
	"rect":     {"x", "y", "width", "height", "rx", "ry"},
	"line":     {"x1", "y1", "x2", "y2"},
	"polyline": {"points"},
	"polygon":  {"points"},
}

// paintAttrs may appear on any shape, with these values only (the mark's dot is filled).
var paintAttrs = map[string][]string{"fill": {"none", "currentColor"}, "stroke": {"none", "currentColor"}}

var geometryRE = regexp.MustCompile(`^[0-9eE.,+\- aAcChHlLmMqQsStTvVzZ]*$`)

// buildSprite reads every Lucide icon from icons and the mark from static, and returns
// the sprite markup and the symbol names.
func buildSprite(icons, static fs.FS) (template.HTML, []string, error) {
	entries, err := fs.ReadDir(icons, lucideIconDir)
	if err != nil {
		return "", nil, fmt.Errorf("ui: icon sprite: %w", err)
	}
	files := map[string]string{markName: markFile}
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".svg"); ok && !e.IsDir() {
			files[name] = path.Join(lucideIconDir, e.Name())
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString(`<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false">`)
	for _, name := range names {
		src := icons
		if name == markName {
			src = static
		}
		sym, err := symbolFrom(src, name, files[name])
		if err != nil {
			return "", nil, err
		}
		b.WriteString(sym)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()), names, nil //nolint:gosec // built from allow-listed shapes only
}

// symbolFrom turns one icon file into a <symbol id="i-name">.
func symbolFrom(fsys fs.FS, name, file string) (string, error) {
	if !iconNameRE.MatchString(name) {
		return "", fmt.Errorf("ui: icon %q: bad name", name)
	}
	raw, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", fmt.Errorf("ui: icon %s: %w", name, err)
	}
	shapes, err := iconShapes(raw)
	if err != nil {
		return "", fmt.Errorf("ui: icon %s: %w", name, err)
	}
	return `<symbol id="i-` + name + `" viewBox="0 0 24 24">` + shapes + `</symbol>`, nil
}

// iconShapes checks the root (an <svg> on the 24 grid) and returns its children,
// re-serialised from the allow-list.
func iconShapes(raw []byte) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var out strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if err := shapeToken(&out, t, depth); err != nil {
				return "", err
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return "", errors.New("text content is not allowed")
			}
		case xml.ProcInst, xml.Directive:
			return "", errors.New("processing instructions and directives are not allowed")
		}
	}
	if out.Len() == 0 {
		return "", errors.New("no shapes")
	}
	return out.String(), nil
}

// svgNS is the only element namespace allowed (Lucide files declare it as the default).
const svgNS = "http://www.w3.org/2000/svg"

func shapeToken(out *strings.Builder, t xml.StartElement, depth int) error {
	if t.Name.Space != "" && t.Name.Space != svgNS {
		return fmt.Errorf("<%s:%s>: only SVG elements are allowed", t.Name.Space, t.Name.Local)
	}
	switch {
	case depth == 1:
		if t.Name.Local != "svg" || attr(t, "viewBox") != "0 0 24 24" {
			return errors.New(`the root must be <svg viewBox="0 0 24 24">`)
		}
		return nil
	case depth > 2:
		return fmt.Errorf("<%s> is nested too deep", t.Name.Local)
	}
	allowed, ok := shapeAttrs[t.Name.Local]
	if !ok {
		return fmt.Errorf("<%s> is not an allowed shape", t.Name.Local)
	}
	out.WriteString("<" + t.Name.Local)
	for _, a := range t.Attr {
		if err := writeAttr(out, a, allowed); err != nil {
			return fmt.Errorf("<%s>: %w", t.Name.Local, err)
		}
	}
	out.WriteString("/>")
	return nil
}

func writeAttr(out *strings.Builder, a xml.Attr, allowed []string) error {
	name, v := a.Name.Local, a.Value
	switch {
	case a.Name.Space != "":
		return fmt.Errorf("namespaced attribute %s:%s", a.Name.Space, name)
	case slices.Contains(allowed, name):
		if !geometryRE.MatchString(v) {
			return fmt.Errorf("attribute %s=%q is not geometry", name, v)
		}
	case slices.Contains(paintAttrs[name], v):
	default:
		return fmt.Errorf("attribute %s=%q is not allowed", name, v)
	}
	out.WriteString(" " + name + `="` + template.HTMLEscapeString(v) + `"`)
	return nil
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
