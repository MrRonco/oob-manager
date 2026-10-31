package rfb

// Encodings (RFC 6143 §7.7 and the community registry). Negative values are
// pseudo-encodings.
const (
	EncRaw         int32 = 0
	EncCopyRect    int32 = 1
	EncRRE         int32 = 2
	EncHextile     int32 = 5
	EncZlib        int32 = 6
	EncTight       int32 = 7
	EncZRLE        int32 = 16
	EncJPEG        int32 = 21
	EncH264        int32 = 50
	EncTightPNG    int32 = -260
	EncDesktopSize int32 = -223
	EncLastRect    int32 = -224
	EncCursor      int32 = -239
	EncDesktopName int32 = -307
)

// allowedEncoding is the default allowlist: picture encodings plus pseudo-encodings
// that change only what the server sends. Pseudo-encodings that would make the browser
// send messages the Filter refuses (QEMU extended key events, ExtendedDesktopSize,
// Fence, ContinuousUpdates, xvp, extended clipboard, extended mouse buttons, …) are
// removed, so the BMC never enables them.
func allowedEncoding(e int32) bool {
	switch e {
	case EncRaw, EncCopyRect, EncRRE, EncHextile, EncZlib, EncTight, EncZRLE, EncJPEG, EncH264,
		EncTightPNG, EncDesktopSize, EncLastRect, EncCursor, EncDesktopName:
		return true
	}
	quality := e >= -32 && e <= -23       // JPEG quality level 0..9
	compression := e >= -256 && e <= -247 // compression level 0..9
	return quality || compression
}

// safeEncoding is the iDRAC8 black-screen workaround set (docs/research/console.md §1.2).
func safeEncoding(e int32) bool {
	return e == EncRaw || e == EncCopyRect || e == EncDesktopSize
}

// FilterEncodings returns the browser's list filtered (in its order) to the allowlist,
// or to Raw/CopyRect/DesktopSize when safe is set. Raw is appended if missing, so the
// server always has an encoding it must support.
func FilterEncodings(encs []int32, safe bool) []int32 {
	keep := allowedEncoding
	if safe {
		keep = safeEncoding
	}
	out := make([]int32, 0, len(encs)+1)
	seen := map[int32]bool{}
	for _, e := range encs {
		if keep(e) && !seen[e] {
			out = append(out, e)
			seen[e] = true
		}
	}
	if !seen[EncRaw] {
		out = append(out, EncRaw)
	}
	return out
}
