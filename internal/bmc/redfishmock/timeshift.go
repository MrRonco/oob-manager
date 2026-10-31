package redfishmock

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// createdKey is the LogEntry property that dates an SEL or Lifecycle log entry.
const createdKey = "Created"

// WithLogTimeShift moves every log entry's Created time by d when it is served, keeping
// each entry's UTC offset and the spacing between entries (README screenshots: captured
// logs are years old). Documents without a Created time are served unchanged.
func WithLogTimeShift(d time.Duration) Option {
	return func(c *config) { c.logShift = d }
}

// WithLogTextReplace replaces from with to in every string of every served log entry
// (README screenshots: a neutral client address instead of the BMC's own). Other
// documents are served unchanged.
func WithLogTextReplace(from, to string) Option {
	return func(c *config) { c.logReplace = append(c.logReplace, from, to) }
}

// rewriteLogs applies WithLogTimeShift and WithLogTextReplace to a served body.
func (s *Server) rewriteLogs(body []byte) []byte {
	if (s.cfg.logShift == 0 && len(s.cfg.logReplace) == 0) || !bytes.Contains(body, []byte(`"`+createdKey+`"`)) {
		return body
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return body
	}
	shift, text := s.cfg.logShift, strings.NewReplacer(s.cfg.logReplace...)
	walkCreated(doc, func(m map[string]any, at time.Time) {
		for k, v := range m {
			m[k] = replaceStrings(v, text)
		}
		m[createdKey] = at.Add(shift).In(at.Location()).Format(time.RFC3339)
	})
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return body
	}
	return out.Bytes()
}

// replaceStrings returns v with r applied to every string in it.
func replaceStrings(v any, r *strings.Replacer) any {
	switch x := v.(type) {
	case string:
		return r.Replace(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = replaceStrings(e, r)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = replaceStrings(e, r)
		}
		return out
	}
	return v
}

// walkCreated calls fn for every object in v with a parseable Created time.
func walkCreated(v any, fn func(map[string]any, time.Time)) {
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x[createdKey].(string); ok {
			if at, err := time.Parse(time.RFC3339, s); err == nil {
				fn(x, at)
			}
		}
		for _, child := range x {
			walkCreated(child, fn)
		}
	case []any:
		for _, child := range x {
			walkCreated(child, fn)
		}
	}
}

// LatestCreated is the newest log entry Created time in the fixture files of dirs, the
// anchor for WithLogTimeShift.
func LatestCreated(dirs ...string) (time.Time, error) {
	var latest time.Time
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			return time.Time{}, err
		}
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: fixture files of a test helper
			if err != nil {
				return time.Time{}, err
			}
			var doc any
			if json.Unmarshal(b, &doc) != nil {
				continue
			}
			walkCreated(doc, func(_ map[string]any, at time.Time) {
				if at.After(latest) {
					latest = at
				}
			})
		}
	}
	if latest.IsZero() {
		return time.Time{}, errors.New("redfishmock: no log entry with a Created time")
	}
	return latest, nil
}
