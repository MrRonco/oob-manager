package api

import (
	"time"

	"oob-manager/internal/fleet"
)

// sectionJSON is one slow poll tier: when its kept value was read, and whether that
// is older than the tier period allows (the UI flags only overdue sections).
type sectionJSON struct {
	AsOf    *time.Time `json:"as_of"`
	Overdue bool       `json:"overdue"`
}

type sectionsJSON struct {
	SEL       sectionJSON `json:"sel"`
	Lifecycle sectionJSON `json:"lifecycle"`
	Inventory sectionJSON `json:"inventory"`
}

// pollTiming is part of the server detail: last fast-tier duration and the interval.
type pollTiming struct {
	// LastPollDurationMS is how long the last snapshot read took (null: never polled).
	LastPollDurationMS *int64       `json:"last_poll_duration_ms"`
	PollIntervalS      int64        `json:"poll_interval_s"`
	Sections           sectionsJSON `json:"sections"`
}

func timingOf(s fleet.ServerState) pollTiming {
	t := pollTiming{PollIntervalS: int64(s.Interval / time.Second), Sections: sectionsJSON{
		SEL:       sectionJSON{AsOf: timePtr(s.SELAsOf), Overdue: s.SELOverdue},
		Lifecycle: sectionJSON{AsOf: timePtr(s.LifecycleAsOf), Overdue: s.LifecycleOverdue},
		Inventory: sectionJSON{AsOf: timePtr(s.InventoryAsOf), Overdue: s.InventoryOverdue},
	}}
	if s.LastPollDuration > 0 {
		ms := s.LastPollDuration.Milliseconds()
		t.LastPollDurationMS = &ms
	}
	return t
}
