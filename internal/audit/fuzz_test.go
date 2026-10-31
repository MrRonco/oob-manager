package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FuzzRedact: no value under a secret-named key survives redaction, at any depth,
// including maps inside lists; the caller's map is never modified.
func FuzzRedact(f *testing.F) {
	f.Add([]byte(`{"password":"x","user":"a"}`))
	f.Add([]byte(`{"nested":{"totp":"123456","ok":1}}`))
	f.Add([]byte(`{"items":[{"secret":"s"},{"name":"n"}]}`))
	f.Add([]byte(`{"a":[[{"Private_Key":"k"}]]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var in map[string]any
		if json.Unmarshal(raw, &in) != nil || in == nil {
			return
		}
		before, _ := json.Marshal(in)
		out := redact(in)
		after, _ := json.Marshal(in)
		if !bytes.Equal(before, after) {
			t.Fatal("redact modified the caller's map")
		}
		assertRedacted(t, out)
	})
}

func assertRedacted(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKey(k) {
				if val != Redacted {
					t.Fatalf("secret key %q kept %v", k, val)
				}
				continue
			}
			assertRedacted(t, val)
		}
	case []any:
		for _, e := range x {
			assertRedacted(t, e)
		}
	}
}

// FuzzGELFEncode: any message encodes to one JSON object followed by exactly one NUL,
// with the text fields round-tripping and field keys reduced to GELF's character set.
func FuzzGELFEncode(f *testing.F) {
	f.Add("host", "short", "full", "key", "value")
	f.Add("", "", "", "id", "\x00nul")
	f.Add("h", "émoji 🎉", "line\nbreak", "bad key!", "v")
	f.Fuzz(func(t *testing.T, host, short, full, key, val string) {
		m := Message{Host: host, Short: short, Full: full, Level: LevelInfo,
			Timestamp: time.Unix(1792000000, 0), Fields: map[string]any{key: val}}
		b, err := m.encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if len(b) == 0 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
			t.Fatal("the frame must end in exactly one NUL")
		}
		var got map[string]any
		if err := json.Unmarshal(b[:len(b)-1], &got); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		if got["short_message"] != jsonRoundTrip(orDash(short)) || got["version"] != "1.1" {
			t.Fatalf("short_message %q for %q", got["short_message"], short)
		}
		for k := range got {
			if strings.HasPrefix(k, "_") && strings.Trim(k[1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
				t.Fatalf("field key %q outside GELF's set", k)
			}
			if k == "_id" {
				t.Fatal("reserved _id emitted")
			}
		}
	})
}

// jsonRoundTrip is what encoding/json makes of s (each invalid UTF-8 byte becomes U+FFFD).
func jsonRoundTrip(s string) string {
	b, _ := json.Marshal(s)
	var out string
	_ = json.Unmarshal(b, &out)
	return out
}

// TestRedactListsOfMaps is the regression for the fuzz finding: a secret inside a list
// of maps was not redacted.
func TestRedactListsOfMaps(t *testing.T) {
	in := map[string]any{
		"items":   []any{map[string]any{"secret": "s", "name": "n"}, []any{map[string]any{"password": "p"}}},
		"targets": []map[string]any{{"token": "t"}},
	}
	out := redact(in)
	assertRedacted(t, out)
	if targets, ok := out["targets"].([]map[string]any); !ok || targets[0]["token"] != Redacted {
		t.Fatal("[]map[string]any not redacted")
	}
	items, _ := in["items"].([]any)
	if first, ok := items[0].(map[string]any); !ok || first["secret"] != "s" {
		t.Fatal("the caller's list was modified")
	}
}
