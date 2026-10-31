package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/maint"
)

type fakeMaint struct {
	windows map[string]maint.Window
	acks    []maint.Ack
}

func (f fakeMaint) Window(id string) (maint.Window, bool) { w, ok := f.windows[id]; return w, ok }

func (f fakeMaint) Acks(id string) []maint.Ack {
	var out []maint.Ack
	for _, a := range f.acks {
		if a.Ref.ServerID == id {
			out = append(out, a)
		}
	}
	return out
}

func (f fakeMaint) AckOf(r maint.EventRef) (maint.Ack, bool) {
	for _, a := range f.acks {
		if a.Ref.ServerID == r.ServerID && a.Ref.Log == r.Log && a.Ref.EntryID == r.EntryID && a.Ref.Created.Equal(r.Created) {
			return a, true
		}
	}
	return maint.Ack{}, false
}

func TestMaintenanceAndAcksInAPI(t *testing.T) {
	ack := maint.Ack{Ref: maint.EventRef{ServerID: "r730xd", Log: "sel", EntryID: "3", Created: t0.Add(3 * time.Minute)},
		By: "oscar", At: t0.Add(time.Hour), Comment: "known"}
	fm := fakeMaint{windows: map[string]maint.Window{
		"r730xd": {ServerID: "r730xd", StartsAt: t0.Add(-time.Hour), EndsAt: t0.Add(3 * time.Hour), Reason: "PSU swap", By: "oscar"},
		"r240":   {ServerID: "r240", StartsAt: t0.Add(24 * time.Hour), Reason: "rack move", By: "olga"},
	}, acks: []maint.Ack{ack}}
	c := &clock{now: t0}
	a := newTestAPI(t, Deps{Maintenance: fm, Now: c.Now})
	body := decode[struct {
		Data []serverSummary `json:"data"`
	}](t, do(t, a, http.MethodGet, "/api/v1/servers", goodToken))
	m, open := body.Data[0].Maintenance, body.Data[1].Maintenance
	if m == nil || !m.Active || m.Reason != "PSU swap" || m.By != "oscar" || m.EndsAt == nil || !m.EndsAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("active window %+v", m)
	}
	if open == nil || open.Active || open.EndsAt != nil {
		t.Fatalf("scheduled until-ended window %+v", open)
	}
	w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd", goodToken)
	d := decode[serverDetail](t, w)
	if len(d.Acks) != 1 || d.Acks[0].EntryID != "3" || d.Acks[0].By != "oscar" || d.Maintenance == nil {
		t.Fatalf("detail %s", w.Body.String())
	}
	if dead := decode[serverDetail](t, do(t, a, http.MethodGet, "/api/v1/servers/r240", goodToken)); dead.Acks == nil {
		t.Fatal("acks must be [] not null")
	}
	ev := getEvents(t, a, "")
	acked := 0
	for _, e := range ev.Data {
		if e.Ack != nil {
			acked++
			if e.ID != "3" || e.Ack.Comment != "known" {
				t.Fatalf("ack on %+v", e)
			}
		}
	}
	if acked != 1 {
		t.Fatalf("%d acked events", acked)
	}
}

func TestMaintenanceFieldsWithoutService(t *testing.T) {
	a := newTestAPI(t, Deps{})
	w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd", goodToken)
	if !strings.Contains(w.Body.String(), `"maintenance":null`) || !strings.Contains(w.Body.String(), `"acks":[]`) {
		t.Fatalf("detail %s", w.Body.String())
	}
}
