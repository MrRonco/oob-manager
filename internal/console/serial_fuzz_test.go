package console

import (
	"bytes"
	"testing"

	"oob-manager/internal/bmc/bmcssh"
)

// FuzzSerialControl: only the three control types decode, with sane sizes; anything
// else is a protocol violation, and decoding never panics.
func FuzzSerialControl(f *testing.F) {
	for _, s := range []string{`{"type":"resize","cols":80,"rows":24}`, `{"type":"break"}`, `{"type":"quit"}`,
		`{"type":"resize","cols":0,"rows":24}`, `{"type":"x"}`, `{"type":"quit","extra":1}`, `{"type":"break"}{}`, `[]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		m, err := parseControl(p)
		if err != nil {
			if err != errSerialProtocol {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if len(p) > MaxSerialControl {
			t.Fatalf("accepted %d bytes", len(p))
		}
		switch m.Type {
		case ctlResize:
			if m.Cols < 1 || m.Cols > 10000 || m.Rows < 1 || m.Rows > 10000 {
				t.Fatalf("resize out of range: %+v", m)
			}
		case ctlBreak, ctlQuit:
			if m.Cols != 0 || m.Rows != 0 {
				t.Fatalf("sizes on %q", m.Type)
			}
		default:
			t.Fatalf("decoded unknown type %q", m.Type)
		}
	})
}

// FuzzSerialInput: the BMC quit key never survives stripQuitKey, nothing else is lost,
// and the count is exact.
func FuzzSerialInput(f *testing.F) {
	f.Add([]byte("ls -l\r"))
	f.Add([]byte{bmcssh.QuitKey})
	f.Add([]byte{'a', bmcssh.QuitKey, 'b', bmcssh.QuitKey, bmcssh.QuitKey})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > MaxSerialInput {
			p = p[:MaxSerialInput] // the relay refuses larger messages before this point
		}
		want := bytes.ReplaceAll(p, []byte{bmcssh.QuitKey}, nil)
		got, n := stripQuitKey(p)
		if bytes.IndexByte(got, bmcssh.QuitKey) >= 0 {
			t.Fatal("the quit key reached the BMC side")
		}
		if !bytes.Equal(got, want) || n != len(p)-len(got) {
			t.Fatalf("stripQuitKey(%q) = %q, %d", p, got, n)
		}
	})
}
