package dell

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware/catalog"
)

// Length caps of kept strings (plan 08 §7.2).
const (
	maxName    = 160
	maxVersion = 64
	maxPath    = 512
	maxURL     = 512
)

var (
	systemIDPattern = regexp.MustCompile(`^[0-9A-F]{4}$`)
	hexIDPattern    = regexp.MustCompile(`^[0-9A-Fa-f]{1,8}$`)
	componentIDPat  = regexp.MustCompile(`^[0-9A-Za-z._-]{1,32}$`)
)

// firmwareTypes are the ComponentType values the check reads. Drivers (DRVR) and
// applications (APAC) are skipped: Dell's drivers share component IDs with the device's
// firmware, and an OS driver version is not a firmware version.
var firmwareTypes = map[string]bool{"FRMW": true, "BIOS": true}

// sizeReader fails with ErrSize once more than max bytes are read (io.LimitReader would
// truncate silently and turn a bomb into a confusing parse error).
type sizeReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (s *sizeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.n += int64(n)
	if s.n > s.max {
		return n, fmt.Errorf("%w: more than %d bytes after decompression", catalog.ErrSize, s.max)
	}
	return n, err
}

// maxTokenGap bounds the bytes between two '<': every XML token starts at or ends before
// one, so this caps what encoding/xml buffers for a single text node or attribute value
// before the per-token checks see it (a 128 MiB text node would otherwise be held in
// memory whole).
const maxTokenGap = 1 << 20

// gapReader fails with ErrSize once more than max bytes pass without a '<'.
type gapReader struct {
	r   io.Reader
	gap int
	max int
}

func (g *gapReader) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	for _, b := range p[:n] {
		if b == '<' {
			g.gap = 0
			continue
		}
		if g.gap++; g.gap > g.max {
			return n, fmt.Errorf("%w: more than %d bytes without markup", catalog.ErrSize, g.max)
		}
	}
	return n, err
}

// Parse reads a gzip-compressed Dell catalog (one gzip member, UTF-16 or UTF-8 XML) and
// keeps the firmware and BIOS releases of the wanted systems. Every bound in lim is
// enforced on every token; a breach is ErrSize or ErrParse.
func Parse(ctx context.Context, gz io.Reader, want catalog.Want, lim catalog.Limits) (catalog.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, lim.ParseTime)
	defer cancel()
	src := bufio.NewReader(gz)
	zr, err := gzip.NewReader(src)
	if err != nil {
		return catalog.Snapshot{}, fmt.Errorf("%w: not gzip", catalog.ErrParse)
	}
	zr.Multistream(false)
	capped := &sizeReader{r: zr, max: lim.MaxDecompressed}
	text, transcoded, err := textReader(capped)
	if err != nil {
		return catalog.Snapshot{}, wrapRead(err)
	}
	p := newParser(ctx, &gapReader{r: text, max: maxTokenGap}, transcoded, want, lim)
	if err := p.run(); err != nil {
		return catalog.Snapshot{}, err
	}
	if _, err := io.Copy(io.Discard, capped); err != nil { // the member's tail, still under the size cap
		return catalog.Snapshot{}, wrapRead(err)
	}
	if err := zr.Reset(src); !errors.Is(err, io.EOF) {
		return catalog.Snapshot{}, fmt.Errorf("%w: more than one gzip member", catalog.ErrParse)
	}
	return p.snap, nil
}

// wrapRead keeps ErrSize and turns every other read failure (corrupt gzip, malformed
// UTF-16, a cancelled parse) into ErrParse.
func wrapRead(err error) error {
	switch {
	case errors.Is(err, catalog.ErrSize), errors.Is(err, catalog.ErrParse):
		return err
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: parse time limit", catalog.ErrParse)
	default:
		return fmt.Errorf("%w: %s", catalog.ErrParse, shortReason(err))
	}
}

// shortReason is a bounded description of a decoder error. The XML decoder quotes
// input in some messages, so the text is cleaned and capped.
func shortReason(err error) string { return textclean.Clean(err.Error(), 120) }

type parser struct {
	ctx    context.Context
	d      *xml.Decoder
	want   catalog.Want
	lim    catalog.Limits
	snap   catalog.Snapshot
	stack  []string
	comp   *component // non-nil inside a top-level SoftwareComponent
	tokens int
	root   bool
}

func newParser(ctx context.Context, r io.Reader, transcoded bool, want catalog.Want, lim catalog.Limits) *parser {
	d := xml.NewDecoder(r)
	d.Strict = true
	d.Entity = map[string]string{} // only the five predefined entities
	d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
		switch l := strings.ToLower(label); {
		case transcoded && (l == "utf-16" || l == "utf-16le" || l == "utf-16be"):
			return in, nil // already UTF-8
		default:
			return nil, fmt.Errorf("unsupported encoding %q", textclean.Clean(label, 32))
		}
	}
	return &parser{ctx: ctx, d: d, want: want, lim: lim, snap: catalog.Snapshot{Models: map[string][]string{}}}
}

func (p *parser) run() error {
	for {
		tok, err := p.d.RawToken()
		if errors.Is(err, io.EOF) {
			if !p.root || len(p.stack) != 0 {
				return fmt.Errorf("%w: truncated document", catalog.ErrParse)
			}
			return nil
		}
		if err != nil {
			return wrapRead(err)
		}
		if err := p.tick(); err != nil {
			return err
		}
		if err := p.token(tok); err != nil {
			return err
		}
	}
}

// tick checks the time limit every 1024 tokens.
func (p *parser) tick() error {
	p.tokens++
	if p.tokens%1024 == 0 && p.ctx.Err() != nil {
		return fmt.Errorf("%w: parse time limit", catalog.ErrParse)
	}
	return nil
}

func (p *parser) token(tok xml.Token) error {
	switch t := tok.(type) {
	case xml.StartElement:
		return p.start(t)
	case xml.EndElement:
		return p.end(t)
	case xml.CharData:
		if len(t) > p.lim.MaxText {
			return fmt.Errorf("%w: a text node is longer than %d bytes", catalog.ErrSize, p.lim.MaxText)
		}
		if p.comp != nil {
			p.comp.text(p.path(), string(t))
		}
	case xml.Directive:
		return fmt.Errorf("%w: DTDs and entity declarations are not allowed", catalog.ErrParse)
	case xml.ProcInst:
		if t.Target != "xml" || p.root {
			return fmt.Errorf("%w: unexpected processing instruction", catalog.ErrParse)
		}
	}
	return nil
}

func (p *parser) start(t xml.StartElement) error {
	if len(p.stack) == 0 && p.root {
		return fmt.Errorf("%w: content after the root element", catalog.ErrParse)
	}
	if len(p.stack) >= p.lim.MaxDepth {
		return fmt.Errorf("%w: elements nested deeper than %d", catalog.ErrParse, p.lim.MaxDepth)
	}
	for _, a := range t.Attr {
		if len(a.Value) > p.lim.MaxAttr {
			return fmt.Errorf("%w: an attribute is longer than %d bytes", catalog.ErrSize, p.lim.MaxAttr)
		}
	}
	p.stack = append(p.stack, t.Name.Local)
	switch {
	case len(p.stack) == 1:
		if t.Name.Local != "Manifest" {
			return fmt.Errorf("%w: the root element is not Manifest", catalog.ErrParse)
		}
		p.root = true
		p.snap.Manifest = manifest(t.Attr)
	case len(p.stack) == 2 && t.Name.Local == "SoftwareComponent":
		p.snap.Components++
		if p.snap.Components > p.lim.MaxComponents {
			return fmt.Errorf("%w: more than %d components", catalog.ErrSize, p.lim.MaxComponents)
		}
		p.comp = newComponent(t.Attr)
	case p.comp != nil:
		return p.comp.start(p.path(), t.Attr, p.lim)
	}
	return nil
}

func (p *parser) end(t xml.EndElement) error {
	if len(p.stack) == 0 || p.stack[len(p.stack)-1] != t.Name.Local {
		return fmt.Errorf("%w: mismatched end element", catalog.ErrParse)
	}
	if p.comp != nil {
		if len(p.stack) == 2 {
			err := p.keep(p.comp)
			p.comp = nil
			p.stack = p.stack[:len(p.stack)-1]
			return err
		}
		p.comp.end(p.path())
	}
	p.stack = p.stack[:len(p.stack)-1]
	return nil
}

// path is the element path inside the current component ("SupportedDevices/Device").
func (p *parser) path() string {
	if len(p.stack) <= 2 {
		return ""
	}
	return strings.Join(p.stack[2:], "/")
}

// keep adds a finished component's entries for the wanted systems.
func (p *parser) keep(c *component) error {
	rel, ok := c.release()
	if !ok {
		return nil
	}
	for _, m := range c.models {
		if !p.want.Wants(m.id, m.display) {
			continue
		}
		if !containsString(p.snap.Models[m.id], m.display) {
			p.snap.Models[m.id] = append(p.snap.Models[m.id], m.display)
		}
		for _, dev := range c.variants() {
			if len(p.snap.Entries) >= p.lim.MaxEntries {
				return fmt.Errorf("%w: more than %d entries for the fleet's systems", catalog.ErrSize, p.lim.MaxEntries)
			}
			p.snap.Entries = append(p.snap.Entries, catalog.Entry{SystemID: m.id, Device: dev, Release: rel})
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func manifest(attrs []xml.Attr) catalog.Manifest {
	m := catalog.Manifest{
		Version:      textclean.Clean(attr(attrs, "version"), maxVersion),
		ReleaseID:    textclean.Clean(attr(attrs, "releaseID"), maxVersion),
		Identifier:   textclean.Clean(attr(attrs, "identifier"), maxVersion),
		BaseLocation: textclean.Clean(attr(attrs, "baseLocation"), maxPath),
	}
	if t, err := time.Parse(time.RFC3339, attr(attrs, "dateTime")); err == nil {
		m.Published = t.UTC()
	}
	return m
}
