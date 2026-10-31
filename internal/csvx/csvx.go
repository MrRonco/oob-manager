// Package csvx writes the app's CSV exports (firmware, sensor history): RFC 4180
// records with CRLF line ends through encoding/csv, streamed to the response, with a
// spreadsheet formula-injection guard on every cell, valid UTF-8 only, and caps on the
// row count and the cell size. Exports carry BMC-supplied text (names, versions), which
// a spreadsheet must never evaluate.
package csvx

import (
	"encoding/csv"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Defaults for Options.
const (
	DefaultMaxRows      = 100_000
	DefaultMaxCellBytes = 4096
	DefaultMaxBytes     = 8 << 20
)

// Errors of the writer. Once a row is refused the writer keeps refusing.
var (
	ErrNoHeader    = errors.New("csvx: write the header once, before any row")
	ErrWidth       = errors.New("csvx: a row has a different number of cells than the header")
	ErrTooManyRows = errors.New("csvx: row limit reached")
	ErrTooLarge    = errors.New("csvx: size limit reached")
)

// Options caps an export; zero values take the defaults.
type Options struct {
	MaxRows      int
	MaxCellBytes int
	// MaxBytes caps the bytes written to the underlying writer (default 8 MiB); a chunk
	// that would cross it is not written and the writer fails with ErrTooLarge.
	MaxBytes int
	// FlushEvery, with Flush, streams a long export: every FlushEvery rows the buffered
	// records are written out and Flush is called (an http.Flusher's Flush).
	FlushEvery int
	Flush      func()
}

// capWriter refuses any write that would take the total past left.
type capWriter struct {
	w    io.Writer
	left int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if len(p) > c.left {
		return 0, ErrTooLarge
	}
	n, err := c.w.Write(p)
	c.left -= n
	return n, err
}

// Writer streams one CSV document. It is not safe for concurrent use.
type Writer struct {
	w       *csv.Writer
	opts    Options
	width   int
	rows    int
	err     error
	started bool
}

// NewWriter writes to w.
func NewWriter(w io.Writer, o Options) *Writer {
	if o.MaxRows <= 0 {
		o.MaxRows = DefaultMaxRows
	}
	if o.MaxCellBytes <= 0 {
		o.MaxCellBytes = DefaultMaxCellBytes
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	cw := csv.NewWriter(&capWriter{w: w, left: o.MaxBytes})
	cw.UseCRLF = true
	return &Writer{w: cw, opts: o}
}

// Header writes the column names; it must be called once, first.
func (w *Writer) Header(cols ...string) error {
	if w.started {
		return ErrNoHeader
	}
	w.started, w.width = true, len(cols)
	return w.write(cols)
}

// Row writes one record of exactly the header's width.
func (w *Writer) Row(cells ...string) error {
	switch {
	case w.err != nil:
		return w.err
	case !w.started:
		return ErrNoHeader
	case len(cells) != w.width:
		return ErrWidth
	case w.rows >= w.opts.MaxRows:
		w.err = ErrTooManyRows
		return w.err
	}
	w.rows++
	if err := w.write(cells); err != nil {
		return err
	}
	if w.opts.Flush != nil && w.opts.FlushEvery > 0 && w.rows%w.opts.FlushEvery == 0 {
		w.w.Flush()
		if err := w.w.Error(); err != nil {
			w.err = err
			return err
		}
		w.opts.Flush()
	}
	return nil
}

func (w *Writer) write(cells []string) error {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = Guard(truncate(strings.ToValidUTF8(c, "�"), w.opts.MaxCellBytes))
	}
	if err := w.w.Write(out); err != nil {
		w.err = err
		return err
	}
	if err := w.w.Error(); err != nil { // a flush of the buffer hit the size cap
		w.err = err
		return err
	}
	return nil
}

// Rows is how many records (header excluded) were written.
func (w *Writer) Rows() int { return w.rows }

// Close flushes buffered records and reports any write error.
func (w *Writer) Close() error {
	w.w.Flush()
	if w.err == nil {
		w.err = w.w.Error()
	}
	return w.err
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// plainNumber is a cell a spreadsheet reads as a number, not a formula.
var plainNumber = regexp.MustCompile(`^[+-]?[0-9]+(\.[0-9]+)?$`)

// Guard neutralises a cell a spreadsheet would evaluate (OWASP CSV injection): one that
// starts with = + - @, a tab or a carriage return, or their full-width forms, also after
// leading white space (any Unicode space: NBSP, ideographic space, a newline) or format
// characters (zero-width, bidi, BOM), gets a leading apostrophe. Plain numbers ("-5", "+12.5") are left
// alone.
func Guard(s string) string {
	if s == "" || plainNumber.MatchString(s) {
		return s
	}
	if s[0] == '\t' || s[0] == '\r' {
		return "'" + s
	}
	// Skip white space and format characters (zero-width, bidi, BOM): a value that did
	// not pass textclean (a config string) must not hide a formula behind them.
	r, _ := utf8.DecodeRuneInString(strings.TrimLeftFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
	}))
	switch r {
	case '=', '+', '-', '@', '＝', '＋', '－', '＠', '\t', '\r':
		return "'" + s
	}
	return s
}

// unsafeName removes everything but [a-z0-9_-] from a filename part.
var unsafeName = regexp.MustCompile(`[^a-z0-9_-]+`)

// Filename is "<prefix>_<scope>_<yyyymmddThhmmZ>.csv" (UTC); scope is reduced to
// [a-z0-9_-] ("all" when nothing is left).
func Filename(prefix, scope string, at time.Time) string {
	scope = unsafeName.ReplaceAllString(strings.ToLower(scope), "")
	if scope == "" {
		scope = "all"
	}
	return prefix + "_" + scope + "_" + at.UTC().Format("20060102T1504Z") + ".csv"
}

// slugUnsafe is everything a Slug drops.
var slugUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// MaxSlug is the longest Slug.
const MaxSlug = 64

// Slug reduces s to [A-Za-z0-9._-] (each run of anything else becomes one "-"), at most
// MaxSlug bytes, for a file name part such as a sensor key ("x" when nothing is left).
func Slug(s string) string {
	s = strings.Trim(slugUnsafe.ReplaceAllString(s, "-"), "-.")
	if len(s) > MaxSlug {
		s = strings.TrimRight(s[:MaxSlug], "-.")
	}
	if s == "" {
		return "x"
	}
	return s
}

// Number formats a value with a "." decimal separator, no exponent and no thousands
// separator, in the fewest digits that read back as the same float64.
func Number(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// Time formats a time as RFC 3339 in UTC (CSV is for machines; the viewer's zone is a
// display matter).
func Time(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Stamp is the UTC time part of an export's file name (yyyymmddThhmmZ).
func Stamp(at time.Time) string { return at.UTC().Format("20060102T1504Z") }

// ContentDisposition is the attachment header for a Filename result (which needs no
// quoting beyond the quotes: it is [a-z0-9_.-] only).
func ContentDisposition(name string) string { return `attachment; filename="` + name + `"` }
