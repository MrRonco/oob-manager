package audit

import (
	"context"
	"log/slog"
	"testing"

	"oob-manager/internal/secrets"
)

func TestSlogHandler(t *testing.T) {
	sink := &captureSink{}
	h := NewSlogHandler(sink, "oob-manager", slog.LevelInfo)
	lg := slog.New(h).With("component", "fleet").WithGroup("bmc")
	lg.Debug("hidden")
	lg.Warn("poll failed", "server", "r240", "password", secrets.New("hunter2"), slog.Group("err", "class", "timeout"))
	lg.Error("boom")
	slog.New(h).Info("plain", "n", 3)

	if len(sink.msgs) != 3 {
		t.Fatalf("got %d messages", len(sink.msgs))
	}
	m := sink.msgs[0]
	if m.Short != "poll failed" || m.Level != 4 || m.Host != "oob-manager" {
		t.Errorf("message = %+v", m)
	}
	want := map[string]any{"component": "fleet", "bmc_server": "r240", "bmc_password": secrets.Redacted,
		"bmc_err_class": "timeout"}
	for k, v := range want {
		if m.Fields[k] != v {
			t.Errorf("field %s = %v, want %v (all: %v)", k, m.Fields[k], v, m.Fields)
		}
	}
	if sink.msgs[1].Level != 3 || sink.msgs[2].Level != 6 || sink.msgs[2].Fields["n"] != int64(3) {
		t.Errorf("levels/fields = %+v / %+v", sink.msgs[1], sink.msgs[2])
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) || h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled wrong")
	}
	if h.WithGroup("") != h {
		t.Error("empty group should return the same handler")
	}
}

func TestSlogHandlerFullSinkDoesNotError(t *testing.T) {
	h := NewSlogHandler(&captureSink{full: true}, "h", slog.LevelDebug)
	slog.New(h).Info("x")
	if err := h.Handle(context.Background(), slog.Record{}); err != nil {
		t.Errorf("Handle = %v", err)
	}
}

func TestSyslogLevel(t *testing.T) {
	cases := map[slog.Level]int{slog.LevelDebug: 7, slog.LevelInfo: 6, slog.LevelWarn: 4, slog.LevelError: 3, slog.LevelError + 4: 3}
	for in, want := range cases {
		if got := syslogLevel(in); got != want {
			t.Errorf("syslogLevel(%v) = %d, want %d", in, got, want)
		}
	}
}
