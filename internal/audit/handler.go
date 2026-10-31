package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// SlogHandler is a slog.Handler that forwards application logs to a Sink as GELF
// (typically the same *Shipper as the audit copy). It never blocks and never fails:
// a full sink drops the record. Values are resolved first, so slog.LogValuer types
// such as secrets.Secret stay redacted. Handlers are immutable; With* return copies.
type SlogHandler struct {
	sink   Sink
	host   string
	level  slog.Leveler
	prefix string
	attrs  map[string]any
}

// NewSlogHandler returns a handler that ships records at or above level.
func NewSlogHandler(sink Sink, host string, level slog.Leveler) *SlogHandler {
	return &SlogHandler{sink: sink, host: host, level: level, attrs: map[string]any{}}
}

// Enabled implements slog.Handler.
func (h *SlogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

// Handle implements slog.Handler.
func (h *SlogHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make(map[string]any, len(h.attrs)+r.NumAttrs()+1)
	for k, v := range h.attrs {
		fields[k] = v
	}
	r.Attrs(func(a slog.Attr) bool {
		addAttr(fields, h.prefix, a)
		return true
	})
	fields["log_type"] = "app"
	h.sink.Enqueue(Message{Host: h.host, Short: r.Message, Timestamp: r.Time, Level: syslogLevel(r.Level), Fields: fields})
	return nil
}

// WithAttrs implements slog.Handler.
func (h *SlogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	attrs := make(map[string]any, len(h.attrs)+len(as))
	for k, v := range h.attrs {
		attrs[k] = v
	}
	for _, a := range as {
		addAttr(attrs, h.prefix, a)
	}
	c := *h
	c.attrs = attrs
	return &c
}

// WithGroup implements slog.Handler.
func (h *SlogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.prefix = h.prefix + name + "_"
	return &c
}

func addAttr(dst map[string]any, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if a.Key == "" && v.Kind() != slog.KindGroup {
		return
	}
	if v.Kind() == slog.KindGroup {
		inner := prefix
		if a.Key != "" {
			inner = prefix + a.Key + "_"
		}
		for _, g := range v.Group() {
			addAttr(dst, inner, g)
		}
		return
	}
	dst[prefix+a.Key] = gelfValue(v)
}

func gelfValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(v.Any())
	}
}

func syslogLevel(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return LevelError
	case l >= slog.LevelWarn:
		return LevelWarn
	case l >= slog.LevelInfo:
		return LevelInfo
	default:
		return LevelDebug
	}
}
