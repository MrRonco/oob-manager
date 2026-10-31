package csvx

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGuard(t *testing.T) {
	cases := map[string]string{
		"2.19.0":            "2.19.0",
		"":                  "",
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")",
		"+1+2":              "'+1+2",
		"-2+3":              "'-2+3",
		"@SUM(A1)":          "'@SUM(A1)",
		"\t=1":              "'\t=1",
		"\r=1":              "'\r=1",
		"  =1":              "'  =1", // leading spaces do not hide a formula
		"＝1":                "'＝1",   // full-width equals sign
		"-5":                "-5",    // a plain number stays a number
		"+12.5":             "+12.5",
		"-0x1p2":            "'-0x1p2",
		"-Inf":              "'-Inf",
		"Backplane 0":       "Backplane 0",
	}
	for in, want := range cases {
		if got := Guard(in); got != want {
			t.Errorf("Guard(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriterRFC4180(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, Options{})
	if err := w.Header("a", "b", "c"); err != nil {
		t.Fatal(err)
	}
	if err := w.Row(`quote "x"`, "comma, here", "line\nbreak"); err != nil {
		t.Fatal(err)
	}
	if err := w.Row("=cmd", "ok", "\xffbad utf8"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "\r\n") || !strings.Contains(buf.String(), "\r\n") {
		t.Fatalf("records end in CRLF: %q", buf.String())
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[1][0] != `quote "x"` || recs[1][2] != "line\nbreak" || recs[2][0] != "'=cmd" ||
		recs[2][2] != "�bad utf8" {
		t.Fatalf("records %q", recs)
	}
	if w.Rows() != 2 {
		t.Fatalf("rows %d", w.Rows())
	}
}

func TestWriterCaps(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, Options{MaxRows: 2, MaxCellBytes: 8})
	_ = w.Header("h")
	if err := w.Row("ééééééé"); err != nil { // 14 bytes, cut on a rune boundary
		t.Fatal(err)
	}
	if err := w.Row("2"); err != nil {
		t.Fatal(err)
	}
	if err := w.Row("3"); !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("third row: %v", err)
	}
	if err := w.Row("4"); !errors.Is(err, ErrTooManyRows) {
		t.Fatal("the error sticks")
	}
	_ = w.Close()
	recs, _ := csv.NewReader(&buf).ReadAll()
	if len(recs) != 3 || recs[1][0] != "éééé" {
		t.Fatalf("records %q", recs)
	}
	if err := NewWriter(&buf, Options{}).Row("x"); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("a row before the header: %v", err)
	}
	h := NewWriter(&buf, Options{})
	_ = h.Header("a", "b")
	if err := h.Row("1"); !errors.Is(err, ErrWidth) {
		t.Fatalf("width: %v", err)
	}
	if err := h.Header("again"); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("a second header: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestWriterReportsWriteErrors(t *testing.T) {
	w := NewWriter(failWriter{}, Options{})
	_ = w.Header("a")
	_ = w.Row("1")
	if err := w.Close(); err == nil {
		t.Fatal("a broken connection must surface on Close")
	}
}

func TestFilenameAndDisposition(t *testing.T) {
	at := time.Date(2026, 10, 23, 14, 5, 9, 0, time.FixedZone("x", -4*3600))
	if got := Filename("firmware", "fleet", at); got != "firmware_fleet_20261023T1805Z.csv" {
		t.Fatalf("filename %q", got)
	}
	if got := Filename("firmware", "r730xd", at); got != "firmware_r730xd_20261023T1805Z.csv" {
		t.Fatalf("filename %q", got)
	}
	if got := Filename("fw", `../x"y;z`, at); got != "fw_xyz_20261023T1805Z.csv" {
		t.Fatalf("unsafe scope %q", got)
	}
	if got := Filename("fw", "", at); got != "fw_all_20261023T1805Z.csv" {
		t.Fatalf("empty scope %q", got)
	}
	if got := ContentDisposition("firmware_fleet_20261023T1805Z.csv"); got != `attachment; filename="firmware_fleet_20261023T1805Z.csv"` {
		t.Fatalf("disposition %q", got)
	}
}

// TestGuardTrimsUnicodeSpace (review S-L3): a spreadsheet ignores more than ASCII spaces
// before a formula.
func TestGuardTrimsUnicodeSpace(t *testing.T) {
	for _, in := range []string{" =1", "　=1", "\n=1", " +1", "  @SUM(A1)", "\v-1+1"} {
		if got := Guard(in); got != "'"+in {
			t.Errorf("Guard(%q) = %q", in, got)
		}
	}
	if got := Guard(" BIOS"); got != " BIOS" {
		t.Errorf("text after a space is kept as it is: %q", got)
	}
}

// TestWriterByteCap (review S-L7): an export stops at MaxBytes with ErrTooLarge.
func TestWriterByteCap(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, Options{MaxBytes: 64})
	_ = w.Header("a")
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = w.Row(strings.Repeat("x", 10))
	}
	if err == nil {
		err = w.Close()
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
	if buf.Len() > 64 {
		t.Fatalf("wrote %d bytes past the cap", buf.Len())
	}
	if !errors.Is(w.Row("y"), ErrTooLarge) || !errors.Is(w.Close(), ErrTooLarge) {
		t.Fatal("the error sticks")
	}
}

// TestGuardSkipsFormatCharacters (review): a cell that did not pass textclean (a config
// value) cannot hide a formula behind a zero-width or bidi character.
func TestGuardSkipsFormatCharacters(t *testing.T) {
	for _, in := range []string{"\u200b=1", "\ufeff+1", "\u202e@SUM(A1)", " \u200b -1+1"} {
		if got := Guard(in); got != "'"+in {
			t.Errorf("Guard(%q) = %q", in, got)
		}
	}
}

func TestWriterFlushesEveryN(t *testing.T) {
	var buf bytes.Buffer
	flushes, seen := 0, []int{}
	w := NewWriter(&buf, Options{FlushEvery: 2, Flush: func() { flushes++; seen = append(seen, buf.Len()) }})
	if err := w.Header("a"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Row("x"); err != nil {
			t.Fatal(err)
		}
	}
	if flushes != 2 || seen[0] != len("a\r\nx\r\nx\r\n") {
		t.Fatalf("flushes %d at %v; want 2, the first after two rows reached the writer", flushes, seen)
	}
	if err := w.Close(); err != nil || buf.String() != "a\r\n"+strings.Repeat("x\r\n", 5) {
		t.Fatalf("%q, %v", buf.String(), err)
	}
	broken := NewWriter(failWriter{}, Options{FlushEvery: 1, Flush: func() { t.Error("flushed after a failed write") }})
	_ = broken.Header("a")
	if err := broken.Row("x"); err == nil {
		t.Error("a write error at the flush was not reported")
	}
}

func TestSlugNumberTime(t *testing.T) {
	for in, want := range map[string]string{"temp:iDRAC.Embedded.1#CPU1Temp": "temp-iDRAC.Embedded.1-CPU1Temp",
		"power:consumed": "power-consumed", "../..": "x", "": "x", "fan:Fan 1A": "fan-Fan-1A",
		strings.Repeat("a", 70): strings.Repeat("a", 64), "é=1": "1"} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{41: "41", 3.31: "3.31", -0.5: "-0.5", 1e21: "1000000000000000000000",
		29.5: "29.5"} {
		if got := Number(in); got != want {
			t.Errorf("Number(%v) = %q, want %q", in, got, want)
		}
	}
	at := time.Date(2026, 10, 23, 14, 5, 9, 0, time.FixedZone("EDT", -4*3600))
	if Time(at) != "2026-10-23T18:05:09Z" || Stamp(at) != "20261023T1805Z" {
		t.Errorf("Time %s Stamp %s", Time(at), Stamp(at))
	}
}

// FuzzField: any cell survives a write and a read unchanged, except the formula guard's
// apostrophe, invalid UTF-8 and the cell cap.
func FuzzField(f *testing.F) {
	for _, s := range []string{"=1+1", "+cmd", "-x", "@SUM", "\tx", "\rx", "a,b", `q"q`, "line\nbreak", "41.5", "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var buf bytes.Buffer
		w := NewWriter(&buf, Options{MaxCellBytes: 1 << 16})
		if err := w.Header("v", "end"); err != nil { // a second column: a lone empty cell is a blank line
			t.Fatal(err)
		}
		if err := w.Row(s, "."); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil || len(recs) != 2 {
			t.Fatalf("read back %q: %v %v", s, recs, err)
		}
		want := Guard(strings.ToValidUTF8(s, "�"))
		// encoding/csv's reader drops carriage returns inside quoted fields; compare without them.
		if got := recs[1][0]; strings.ReplaceAll(got, "\r", "") != strings.ReplaceAll(want, "\r", "") {
			t.Fatalf("cell %q came back %q, want %q", s, got, want)
		}
	})
}
