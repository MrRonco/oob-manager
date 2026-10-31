package metrics

import "strings"

// spec declares a family. allSpecs is the only list; output follows its order.
type spec struct {
	name, help string
	typ        Type
}

// builder accumulates samples for one scrape. It is local to a single render and is
// discarded afterwards; the families it returns are fresh values.
type builder struct {
	specs     []spec
	declared  map[string]bool
	samples   map[string][]Sample
	seen      map[string]bool
	maxSeries int
	dropped   int
}

func newBuilder(specs []spec, maxSeriesPerFamily int) *builder {
	d := make(map[string]bool, len(specs))
	for _, s := range specs {
		d[s.name] = true
	}
	return &builder{specs: specs, declared: d, samples: map[string][]Sample{}, seen: map[string]bool{}, maxSeries: maxSeriesPerFamily}
}

// add records one sample. Label values are sanitized; a duplicate label set, an
// undeclared family or a family at its cap is dropped and counted.
func (b *builder) add(name string, v float64, labels ...Label) {
	ls := make([]Label, len(labels))
	var key strings.Builder
	key.WriteString(name)
	for i, l := range labels {
		ls[i] = Label{Name: l.Name, Value: SanitizeLabelValue(l.Value)}
		key.WriteString("\x00" + ls[i].Name + "\x00" + ls[i].Value)
	}
	k := key.String()
	if b.seen[k] || !b.declared[name] || len(b.samples[name]) >= b.maxSeries {
		b.dropped++
		return
	}
	b.seen[k] = true
	b.samples[name] = append(b.samples[name], Sample{Labels: ls, Value: v})
}

// drop counts series left out before reaching add (per-server list caps).
func (b *builder) drop(n int) { b.dropped += max(n, 0) }

// families returns the declared families in spec order, then the dropped counter.
func (b *builder) families() []Family {
	out := make([]Family, 0, len(b.specs)+1)
	for _, s := range b.specs {
		out = append(out, Family{Name: s.name, Help: s.help, Type: s.typ, Samples: b.samples[s.name]})
	}
	return append(out, Family{Name: "oob_scrape_series_dropped", Type: Gauge,
		Help:    "Series left out of this scrape by the cardinality caps or as duplicates.",
		Samples: []Sample{{Value: float64(b.dropped)}}})
}
