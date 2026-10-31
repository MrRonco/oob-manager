package console

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// reasonQuit: the user ended the console with the toolbar's Quit (Ctrl-\) control.
const reasonQuit endReason = "quit"

type serialResult struct {
	reason    endReason
	toBrowser int64
	toBMC     int64
	dropped   int64
	breaks    int64
}

type serialCounters struct {
	toBrowser, toBMC, dropped, breaks, lastInput atomic.Int64
}

// relaySerial runs one serial session: BMC output to the browser as binary messages,
// browser keystrokes (quit key removed) and control messages to the BMC, until a side
// closes, a limit is hit, check fails or ctx is cancelled (takeover, shutdown). The
// pumps use their own context so the final "end" status still reaches the browser.
func relaySerial(ctx context.Context, peer SerialPeer, link SerialLink, lim relayLimits, check Watchdog) serialResult {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	ioCtx, ioCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer ioCancel()
	var c serialCounters
	start := time.Now()
	c.lastInput.Store(start.UnixNano())
	sendStatus(ioCtx, peer, statusMsg{Type: "connected"})

	var wg sync.WaitGroup
	wg.Go(func() { cancel(pumpOutput(ioCtx, link, peer, &c)) })
	wg.Go(func() { cancel(pumpInput(ioCtx, peer, link, &c)) })
	reason := watch(ctx, start, &c.lastInput, lim, check)
	cancel(reason)
	if cause, ok := context.Cause(ctx).(endReason); ok {
		reason = cause
	}
	if reason == reasonQuit {
		_ = link.Quit()
	} else {
		_ = link.Close()
	}
	wctx, wcancel := context.WithTimeout(ioCtx, statusWait)
	sendStatus(wctx, peer, statusMsg{Type: "end", Reason: string(reason)})
	wcancel()
	ioCancel()
	wg.Wait()
	return serialResult{reason: reason, toBrowser: c.toBrowser.Load(), toBMC: c.toBMC.Load(),
		dropped: c.dropped.Load(), breaks: c.breaks.Load()}
}

// pumpOutput copies console output to the browser.
func pumpOutput(ctx context.Context, link SerialLink, peer SerialPeer, c *serialCounters) endReason {
	buf := make([]byte, serialChunk)
	for {
		n, err := link.Read(buf)
		if n > 0 {
			if werr := peer.Write(ctx, MessageBinary, buf[:n]); werr != nil {
				return reasonBrowserClosed
			}
			c.toBrowser.Add(int64(n))
		}
		if err != nil {
			return reasonBMCClosed
		}
	}
}

// pumpInput forwards keystrokes and applies control messages; it returns why it stopped.
func pumpInput(ctx context.Context, peer SerialPeer, link SerialLink, c *serialCounters) endReason {
	for {
		typ, p, err := peer.Read(ctx)
		if err != nil {
			return reasonBrowserClosed
		}
		if r := handleInput(typ, p, link, c); r != "" {
			return r
		}
	}
}

func handleInput(typ MessageType, p []byte, link SerialLink, c *serialCounters) endReason {
	if typ != MessageText {
		if typ != MessageBinary || len(p) > MaxSerialInput {
			return reasonProtocol
		}
		data, dropped := stripQuitKey(p)
		c.dropped.Add(int64(dropped))
		c.lastInput.Store(time.Now().UnixNano())
		if len(data) == 0 {
			return ""
		}
		if _, err := link.Write(data); err != nil {
			return reasonBMCClosed
		}
		c.toBMC.Add(int64(len(data)))
		return ""
	}
	m, err := parseControl(p)
	if err != nil {
		return reasonProtocol
	}
	return applyControl(m, link, c)
}

func applyControl(m controlMsg, link SerialLink, c *serialCounters) endReason {
	switch m.Type {
	case ctlQuit:
		return reasonQuit
	case ctlBreak:
		c.lastInput.Store(time.Now().UnixNano())
		c.breaks.Add(1)
		if err := link.Break(); err != nil && !errors.Is(err, context.Canceled) {
			return reasonBMCClosed
		}
	case ctlResize:
		if err := link.Resize(TermSize{Cols: m.Cols, Rows: m.Rows}); err != nil {
			return reasonBMCClosed
		}
	}
	return ""
}
