package metrics

import "testing"

func TestBuilderDedupSanitizeAndCap(t *testing.T) {
	b := newBuilder([]spec{{"oob_x", "X.", Gauge}, {"oob_y", "Y.", Counter}}, 3)
	b.add("oob_x", 1, Label{"server", "a\"\n"})
	b.add("oob_x", 2, Label{"server", "a\""}) // same label set after sanitizing: dropped
	b.add("oob_x", 3, Label{"server", "b"})
	b.add("oob_x", 4, Label{"server", "c"})
	b.add("oob_x", 5, Label{"server", "d"}) // over the family cap
	b.add("oob_unknown", 1)                 // not declared
	b.add("oob_y", 7)
	fams := b.families()
	if len(fams) != 3 {
		t.Fatalf("families = %d", len(fams))
	}
	x := fams[0]
	if len(x.Samples) != 3 || x.Samples[0].Labels[0].Value != `a"` || x.Samples[0].Value != 1 {
		t.Fatalf("oob_x = %+v", x.Samples)
	}
	if fams[1].Name != "oob_y" || len(fams[1].Samples) != 1 {
		t.Fatalf("oob_y = %+v", fams[1])
	}
	last := fams[2]
	if last.Name != "oob_scrape_series_dropped" || last.Samples[0].Value != 3 {
		t.Fatalf("dropped = %+v", last)
	}
}

func TestSpecsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range allSpecs() {
		if !validName(s.name) || seen[s.name] || s.help == "" {
			t.Errorf("bad spec %+v", s)
		}
		if (s.typ == Counter) != (len(s.name) > 6 && s.name[len(s.name)-6:] == "_total") {
			t.Errorf("%s: counters and only counters end in _total", s.name)
		}
		seen[s.name] = true
	}
}
