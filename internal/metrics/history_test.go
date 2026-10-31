package metrics

import (
	"strings"
	"testing"
	"time"
)

// TestHistoryFamiliesWaitForTheFirstPass: before the janitor's first pass (or without
// the history) no oob_history_* series is written; zero watermarks read 0.
func TestHistoryFamiliesWaitForTheFirstPass(t *testing.T) {
	cfg := fullConfig(staticFleet{states: nil})
	cfg.History = func() HistoryState { return HistoryState{} }
	if body := render(t, cfg); strings.Contains(body, "oob_history_rows{") {
		t.Errorf("history families before the first pass:\n%s", body)
	}
	cfg.History = func() HistoryState { return HistoryState{Ready: true, PruneTook: time.Second} }
	body := render(t, cfg)
	if !strings.Contains(body, `oob_history_rollup_last_timestamp_seconds{tier="hourly"} 0`) ||
		!strings.Contains(body, "oob_history_prune_duration_seconds 1") {
		t.Errorf("zero watermarks:\n%s", body)
	}
}
