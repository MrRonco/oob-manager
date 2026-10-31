package metrics

import (
	"bufio"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
)

// ContentType is the media type of the text exposition format 0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Type is a metric family type.
type Type string

// Family types used here (no histograms or summaries).
const (
	Gauge   Type = "gauge"
	Counter Type = "counter"
)

// Label is one name="value" pair. Names are fixed in code; values are sanitized by
// the builder before they get here.
type Label struct {
	Name, Value string
}

// Sample is one series of a family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a metric with its HELP, TYPE and samples. Families without samples are
// not written.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

var errShort = errors.New("metrics: short write")

// Write renders fams in order in the text exposition format.
func Write(w io.Writer, fams []Family) error {
	bw := bufio.NewWriter(w)
	for _, f := range fams {
		if len(f.Samples) == 0 {
			continue
		}
		writeFamily(bw, f)
	}
	return bw.Flush()
}

// writeFamily writes into a bufio.Writer, whose errors are sticky and reported by Flush.
func writeFamily(bw *bufio.Writer, f Family) {
	_, _ = bw.WriteString("# HELP " + f.Name + " " + escapeHelp(f.Help) + "\n")
	_, _ = bw.WriteString("# TYPE " + f.Name + " " + string(f.Type) + "\n")
	for _, s := range f.Samples {
		_, _ = bw.WriteString(f.Name)
		writeLabels(bw, s.Labels)
		_, _ = bw.WriteString(" " + formatValue(s.Value) + "\n")
	}
}

func writeLabels(bw *bufio.Writer, ls []Label) {
	if len(ls) == 0 {
		return
	}
	_ = bw.WriteByte('{')
	for i, l := range ls {
		if i > 0 {
			_ = bw.WriteByte(',')
		}
		_, _ = bw.WriteString(l.Name + `="` + escapeLabel(l.Value) + `"`)
	}
	_ = bw.WriteByte('}')
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	default:
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
}

// escapeLabel escapes a label value: backslash, double quote and line feed.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes HELP text: backslash and line feed.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// validName reports whether s matches [a-zA-Z_:][a-zA-Z0-9_:]*.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		alpha := r == '_' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !alpha && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}
