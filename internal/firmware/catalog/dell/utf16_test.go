package dell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"unicode/utf16"
)

func encode16(s string, little, bom bool) []byte {
	var out []byte
	put := func(u uint16) {
		if little {
			out = binary.LittleEndian.AppendUint16(out, u)
		} else {
			out = binary.BigEndian.AppendUint16(out, u)
		}
	}
	if bom {
		put(0xFEFF)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		put(u)
	}
	return out
}

func readAll(t *testing.T, b []byte) (string, bool, error) {
	t.Helper()
	r, transcoded, err := textReader(bytes.NewReader(b))
	if err != nil {
		return "", false, err
	}
	out, err := io.ReadAll(r)
	return string(out), transcoded, err
}

func TestTextReaderTranscodes(t *testing.T) {
	const s = `<a x="é">Dell 𝄞 ✓</a>` // includes a surrogate pair (U+1D11E)
	for _, little := range []bool{true, false} {
		got, tr, err := readAll(t, encode16(s, little, true))
		if err != nil || !tr || got != s {
			t.Errorf("little=%v: %q %v %v", little, got, tr, err)
		}
	}
	got, tr, err := readAll(t, []byte(s))
	if err != nil || tr || got != s {
		t.Errorf("UTF-8 passes through: %q %v %v", got, tr, err)
	}
	if got, _, err := readAll(t, nil); err != nil || got != "" {
		t.Errorf("empty input: %q %v", got, err)
	}
	long := bytes.Repeat([]byte("ab"), 10000)
	if got, _, err := readAll(t, encode16(string(long), true, true)); err != nil || got != string(long) {
		t.Errorf("long input: %d bytes, %v", len(got), err)
	}
}

func TestTextReaderRefusesMalformed(t *testing.T) {
	bom := []byte{0xFF, 0xFE}
	cases := map[string][]byte{
		"odd byte count":       append(append([]byte{}, bom...), 'a', 0, 'b'),
		"lone high surrogate":  append(append([]byte{}, bom...), 0x34, 0xD8, 'a', 0),
		"high at the end":      append(append([]byte{}, bom...), 0x34, 0xD8),
		"lone low surrogate":   append(append([]byte{}, bom...), 0x1E, 0xDD),
		"high then high again": append(append([]byte{}, bom...), 0x34, 0xD8, 0x34, 0xD8),
	}
	for name, b := range cases {
		if _, _, err := readAll(t, b); !errors.Is(err, errUTF16) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzUTF16Reader(f *testing.F) {
	f.Add(encode16(`<Manifest version="1"/>`, true, true))
	f.Add([]byte{0xFE, 0xFF, 0xD8, 0x34, 0xDD, 0x1E})
	f.Add([]byte("plain"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _, err := textReader(bytes.NewReader(b))
		if err != nil {
			return
		}
		out, err := io.ReadAll(r)
		if err == nil && !utf8Valid(out) && bytes.HasPrefix(b, []byte{0xFF, 0xFE}) {
			t.Fatalf("transcoded output is not UTF-8: %q", out)
		}
	})
}

func utf8Valid(b []byte) bool { return bytes.Equal([]byte(string(bytes.ToValidUTF8(b, nil))), b) }
