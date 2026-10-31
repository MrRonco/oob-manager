package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"oob-manager/internal/bmc/bmcssh"
)

// MessageType is the kind of a WebSocket message on the serial console socket.
type MessageType int

// Message types: binary messages carry terminal bytes (both directions); text messages
// carry the small JSON control protocol below.
const (
	MessageBinary MessageType = iota + 1
	MessageText
)

// Serial socket limits.
const (
	// MaxSerialInput bounds one binary message from the browser (keystrokes or a paste).
	MaxSerialInput = 4096
	// MaxSerialControl bounds one control message from the browser.
	MaxSerialControl = 256
	serialChunk      = 4096
)

// SerialPeer is the browser end of a serial console (a WebSocket). Read must return
// when ctx is cancelled; Write must be safe to call concurrently with Read.
type SerialPeer interface {
	Read(ctx context.Context) (MessageType, []byte, error)
	Write(ctx context.Context, typ MessageType, p []byte) error
}

// Control messages from the browser: a closed enum. Anything else ends the session
// (reason "protocol"): the browser can only send keystrokes, a size, a break and quit.
type controlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

const (
	ctlResize = "resize"
	ctlBreak  = "break"
	ctlQuit   = "quit"
)

var errSerialProtocol = errors.New("console: serial protocol violation")

// parseControl decodes one control message strictly (no unknown fields, known type,
// sane size).
func parseControl(p []byte) (controlMsg, error) {
	if len(p) > MaxSerialControl {
		return controlMsg{}, errSerialProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.DisallowUnknownFields()
	var m controlMsg
	if err := dec.Decode(&m); err != nil || dec.More() {
		return controlMsg{}, errSerialProtocol
	}
	switch m.Type {
	case ctlResize:
		if m.Cols < 1 || m.Cols > 10000 || m.Rows < 1 || m.Rows > 10000 {
			return controlMsg{}, errSerialProtocol
		}
	case ctlBreak, ctlQuit:
		if m.Cols != 0 || m.Rows != 0 {
			return controlMsg{}, errSerialProtocol
		}
	default:
		return controlMsg{}, errSerialProtocol
	}
	return m, nil
}

// stripQuitKey removes the BMC console's quit key from browser input: the toolbar's
// "Quit" control ends the console instead, so typed input can never detach from
// `console com2`. It returns the filtered bytes and how many were removed.
func stripQuitKey(p []byte) ([]byte, int) {
	n := bytes.Count(p, []byte{bmcssh.QuitKey})
	if n == 0 {
		return p, 0
	}
	return bytes.ReplaceAll(p, []byte{bmcssh.QuitKey}, nil), n
}

// Server → browser status messages.
type statusMsg struct {
	Type   string `json:"type"`             // "connected", "error" or "end"
	Reason string `json:"reason,omitempty"` // end reason
	Class  string `json:"class,omitempty"`  // error class
}

func sendStatus(ctx context.Context, p SerialPeer, m statusMsg) {
	b, _ := json.Marshal(m)
	_ = p.Write(ctx, MessageText, b)
}
