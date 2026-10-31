package metrics

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestWriteFormat(t *testing.T) {
	fams := []Family{
		{Name: "oob_a", Help: "A gauge.", Type: Gauge, Samples: []Sample{
			{Value: 1},
		}},
		{Name: "oob_empty", Help: "Never written.", Type: Gauge},
		{Name: "oob_b_total", Help: "Back\\slash and\nnewline.", Type: Counter, Samples: []Sample{
			{Labels: []Label{{"server", "s1"}, {"stage", "password"}}, Value: 3},
			{Labels: []Label{{"server", "s\"2\\\n"}}, Value: 0.5},
		}},
		{Name: "oob_c", Help: "Specials.", Type: Gauge, Samples: []Sample{
			{Labels: []Label{{"v", "nan"}}, Value: math.NaN()},
			{Labels: []Label{{"v", "inf"}}, Value: math.Inf(1)},
			{Labels: []Label{{"v", "-inf"}}, Value: math.Inf(-1)},
			{Labels: []Label{{"v", "big"}}, Value: 1.5e12},
			{Labels: []Label{{"v", "neg"}}, Value: -2},
		}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, fams); err != nil {
		t.Fatal(err)
	}
	want := `# HELP oob_a A gauge.
# TYPE oob_a gauge
oob_a 1
# HELP oob_b_total Back\\slash and\nnewline.
# TYPE oob_b_total counter
oob_b_total{server="s1",stage="password"} 3
oob_b_total{server="s\"2\\\n"} 0.5
# HELP oob_c Specials.
# TYPE oob_c gauge
oob_c{v="nan"} NaN
oob_c{v="inf"} +Inf
oob_c{v="-inf"} -Inf
oob_c{v="big"} 1.5e+12
oob_c{v="neg"} -2
`
	if got := buf.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errShort
	}
	f.n--
	return len(p), nil
}

func TestWritePropagatesErrors(t *testing.T) {
	fams := []Family{{Name: "oob_a", Help: "h", Type: Gauge, Samples: []Sample{{Value: 1}}}}
	if err := Write(&failWriter{}, fams); err == nil {
		t.Fatal("write error swallowed")
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	long := strings.Repeat("é", MaxLabelValueBytes)
	tests := []struct{ in, want string }{
		{"CPU1 Temp", "CPU1 Temp"},
		{"a\x00b\x1fc\x7fd", "abcd"},
		{"bad\xffutf8", "bad�utf8"},
		{"  padded\t", "padded"},
		{"line\nbreak", "linebreak"},
	}
	for _, tc := range tests {
		if got := SanitizeLabelValue(tc.in); got != tc.want {
			t.Errorf("SanitizeLabelValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	got := SanitizeLabelValue(long)
	if len(got) > MaxLabelValueBytes || !strings.HasPrefix(long, got) || len(got) < MaxLabelValueBytes-1 {
		t.Fatalf("truncation broke a rune or the cap: %d bytes", len(got))
	}
}

func TestValidMetricName(t *testing.T) {
	for _, ok := range []string{"oob_a", "oob_server_up", "a:b_c1"} {
		if !validName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "1abc", "oob-a", "oob a", "oob_é"} {
		if validName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
