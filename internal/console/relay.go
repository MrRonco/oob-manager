package console

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/console/rfb"
)

// relayLimits bound one session.
type relayLimits struct {
	idle  time.Duration // no user input for this long ends the session
	max   time.Duration // absolute session length
	check time.Duration // how often limits and the session watchdog are evaluated
}

type relayResult struct {
	reason    endReason
	toBrowser int64
	toBMC     int64
	dropped   int64
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// relay pumps BMC→browser bytes unchanged and browser→BMC messages through the
// allowlisting filter until one side closes, a limit is hit, check fails or ctx is
// cancelled (takeover, shutdown). It closes both connections before returning.
func relay(ctx context.Context, browser, bmcConn net.Conn, fc rfb.FilterConfig, lim relayLimits,
	check func(context.Context) error) relayResult {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var res relayResult
	var toBrowser, toBMC, dropped atomic.Int64
	var lastInput atomic.Int64
	start := time.Now()
	lastInput.Store(start.UnixNano())

	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := io.Copy(countingWriter{browser, &toBrowser}, bmcConn)
		cancel(closeReason(err, reasonBMCClosed))
	})
	wg.Go(func() {
		cancel(pumpClient(browser, countingWriter{bmcConn, &toBMC}, fc, &lastInput, &dropped))
	})
	res.reason = watch(ctx, start, &lastInput, lim, check)
	cancel(res.reason)
	_ = browser.Close()
	_ = bmcConn.Close()
	wg.Wait()
	if cause, ok := context.Cause(ctx).(endReason); ok {
		res.reason = cause
	}
	res.toBrowser, res.toBMC, res.dropped = toBrowser.Load(), toBMC.Load(), dropped.Load()
	return res
}

// pumpClient forwards filtered browser messages; it returns why it stopped.
func pumpClient(browser io.Reader, bmcConn io.Writer, fc rfb.FilterConfig, lastInput, dropped *atomic.Int64) endReason {
	f := rfb.NewFilter(browser, fc)
	for {
		m, err := f.Next()
		if err != nil {
			return closeReason(err, reasonBrowserClosed)
		}
		if m.Forward == nil {
			dropped.Add(1)
			continue
		}
		if _, err := bmcConn.Write(m.Forward); err != nil {
			return reasonBMCClosed
		}
		if m.Input {
			lastInput.Store(time.Now().UnixNano())
		}
	}
}

// closeReason maps a read error: a protocol violation, or a normal close of that side.
func closeReason(err error, normal endReason) endReason {
	if errors.Is(err, rfb.ErrProtocol) {
		return reasonProtocol
	}
	return normal
}

// watch evaluates the limits every lim.check until ctx ends; it returns the reason the
// session must end ("" never: ctx's cause wins when it was the pumps).
func watch(ctx context.Context, start time.Time, lastInput *atomic.Int64, lim relayLimits,
	check func(context.Context) error) endReason {
	t := time.NewTicker(lim.check)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if r, ok := context.Cause(ctx).(endReason); ok {
				return r
			}
			return reasonShutdown
		case now := <-t.C:
			if r := limitReached(ctx, now, start, time.Unix(0, lastInput.Load()), lim, check); r != "" {
				return r
			}
		}
	}
}

func limitReached(ctx context.Context, now, start, last time.Time, lim relayLimits, check func(context.Context) error) endReason {
	switch {
	case now.Sub(start) >= lim.max:
		return reasonMax
	case now.Sub(last) >= lim.idle:
		return reasonIdle
	}
	if check == nil {
		return ""
	}
	if err := check(ctx); err != nil {
		var r endReason
		if errors.As(err, &r) {
			return r
		}
		return reasonSession
	}
	return ""
}
