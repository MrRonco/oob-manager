package ui

import (
	"context"
	"net/url"

	"oob-manager/internal/authz"
	"oob-manager/internal/fleet"
	"oob-manager/internal/history"
	"oob-manager/internal/history/svg"
	"oob-manager/internal/store"
)

// sparkView is one 24 h sparkline of the Hardware tab's Status panel.
type sparkView struct {
	ID, Href, ViewBox, D, Title, Desc string
}

// sparkSet are the Status panel's sparklines (nil: no history for that sensor).
type sparkSet struct {
	Hottest, Inlet, Draw *sparkView
}

type sparkWant struct {
	key, id, panel string
	slot           **sparkView
}

// sparksFor reads the three sparklines (the hottest temperature, the inlet, the power
// draw) from the history in one chart read; nothing when the history is off, the
// viewer may not see it or a sensor has no samples.
func (s *server) sparksFor(ctx context.Context, v ServerView, sum summaryRow, sess session) sparkSet {
	var set sparkSet
	if !s.historyOn() || s.d.Authorize(sess.id.Principal(), authz.ViewHistory, true) != nil {
		return set
	}
	keys, ok := s.historyKeys(ctx, v.ID)
	if !ok || len(keys) == 0 {
		return set
	}
	wants := []sparkWant{{sum.HottestKey, "sp-hot", "h-temp", &set.Hottest}, {sum.InletKey, "sp-inlet", "h-temp", &set.Inlet},
		{fleet.KeyPowerWatts, "sp-draw", "h-power", &set.Draw}}
	var ks []store.SensorKey
	for _, w := range wants {
		if k, found := keyByName(keys, w.key); found && !containsKey(ks, k.Key) {
			ks = append(ks, k)
		}
	}
	if len(ks) == 0 {
		return set
	}
	p := history.SparkPlan(s.d.History.Now())
	series, err := s.d.History.Chart(ctx, ks, p)
	if err != nil {
		s.d.Logger.Warn("ui sparklines failed", "server", v.ID, "err", err)
		return set
	}
	for _, w := range wants {
		for _, sr := range series {
			if sr.Key.Key == w.key && len(sr.Buckets) > 0 {
				*w.slot = sparkOf(v.ID, w, sr, p, histUnitOf(sr.Key.Unit, sess.view.Temp))
			}
		}
	}
	return set
}

func containsKey(ks []store.SensorKey, key string) bool {
	_, ok := keyByName(ks, key)
	return ok
}

func sparkOf(id string, w sparkWant, sr history.Series, p history.Plan, u histUnit) *sparkView {
	sp := svg.Sparkline(u.buckets(sr.Buckets), p.From, p.To, p.Step)
	q := url.Values{"range": {string(history.Range24h)}, "focus": {sr.Key.Key}}
	sm := sr.Summary
	return &sparkView{ID: w.id, Href: "/servers/" + id + "/history?" + q.Encode() + "#" + w.panel, ViewBox: sp.ViewBox,
		D: sp.D, Title: history.Label(sr.Key) + ", last 24 hours",
		Desc: "Minimum " + u.text(sm.Min) + ", average " + u.text(sm.Avg) + ", maximum " + u.text(sm.Max) + "."}
}
