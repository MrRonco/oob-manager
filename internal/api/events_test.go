package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

type eventsBody struct {
	Data []eventJSON `json:"data"`
	Meta eventMeta   `json:"meta"`
}

func getEvents(t *testing.T, a *API, query string) eventsBody {
	t.Helper()
	w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/events"+query, goodToken)
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
	}
	return decode[eventsBody](t, w)
}

func ids(es []eventJSON) string {
	var out []string
	for _, e := range es {
		out = append(out, e.ID)
	}
	return strings.Join(out, ",")
}

func TestEventsPaginateNewestFirst(t *testing.T) {
	a := newTestAPI(t, Deps{})
	first := getEvents(t, a, "?limit=3")
	if ids(first.Data) != "7,6,5" || first.Meta.Total != 7 || first.Meta.Limit != 3 || first.Meta.NextCursor == "" ||
		first.Meta.Complete || !first.Meta.Available || first.Meta.Log != "sel" {
		t.Fatalf("page 1 %s %+v", ids(first.Data), first.Meta)
	}
	if !strings.Contains(first.Data[0].Message, "<b>") {
		t.Fatal("messages are data: JSON-encoded, not stripped")
	}
	second := getEvents(t, a, "?limit=3&cursor="+url.QueryEscape(first.Meta.NextCursor))
	if ids(second.Data) != "4,3,2" || second.Meta.NextCursor == "" {
		t.Fatalf("page 2 %s %+v", ids(second.Data), second.Meta)
	}
	last := getEvents(t, a, "?limit=3&cursor="+url.QueryEscape(second.Meta.NextCursor))
	if ids(last.Data) != "1" || last.Meta.NextCursor != "" {
		t.Fatalf("page 3 %s %+v", ids(last.Data), last.Meta)
	}
	if d := getEvents(t, a, ""); len(d.Data) != 7 || d.Meta.Limit != DefaultEventLimit {
		t.Fatalf("default limit %+v", d.Meta)
	}
}

func TestEventsSince(t *testing.T) {
	a := newTestAPI(t, Deps{})
	since := t0.Add(5 * time.Minute).Format(time.RFC3339)
	got := getEvents(t, a, "?since="+url.QueryEscape(since))
	if ids(got.Data) != "7,6" || got.Meta.Total != 2 {
		t.Fatalf("since %s %+v", ids(got.Data), got.Meta)
	}
}

func TestEventsBadQueries(t *testing.T) {
	a := newTestAPI(t, Deps{})
	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?since=yesterday", "?cursor=!!!",
		"?cursor=" + strings.Repeat("A", 300), "?cursor=bm9waXBl", "?cursor=eHx5", "?log=audit"} {
		p := assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd/events"+q, goodToken), http.StatusBadRequest)
		if strings.Contains(p.Detail, "audit") || strings.Contains(p.Detail, "yesterday") {
			t.Errorf("%s: detail echoes input: %q", q, p.Detail)
		}
	}
	assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers/ghost/events", goodToken), http.StatusNotFound)
}

func TestLifecycleLogAndUnavailable(t *testing.T) {
	st := healthyState()
	st.Lifecycle, st.HasLifecycle = bmc.NewEventLog("/lc", []bmc.Event{{ID: "b"}, {ID: "a"}, {ID: "10"}}, true), true
	a := newTestAPI(t, Deps{Fleet: staticFleet{states: []fleet.ServerState{st}, polled: true}})
	got := getEvents(t, a, "?log=lifecycle&limit=2")
	if ids(got.Data) != "b,a" || !got.Meta.Complete || got.Meta.Log != "lifecycle" || got.Data[0].Created != nil {
		t.Fatalf("lifecycle %s %+v", ids(got.Data), got.Meta)
	}
	next := getEvents(t, a, "?log=lifecycle&limit=2&cursor="+url.QueryEscape(got.Meta.NextCursor))
	if ids(next.Data) != "10" {
		t.Fatalf("undated cursor page %s", ids(next.Data))
	}
	st.HasSEL, st.SEL = false, bmc.EventLog{}
	a = newTestAPI(t, Deps{Fleet: staticFleet{states: []fleet.ServerState{st}, polled: true}})
	if got := getEvents(t, a, ""); got.Meta.Available || len(got.Data) != 0 || got.Data == nil {
		t.Fatalf("unavailable SEL %+v", got)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	for _, p := range []position{{created: t0, id: "42"}, {id: "x|y"}} {
		got, ok := decodeCursor(encodeCursor(p))
		if !ok || !got.created.Equal(p.created) || got.id != p.id {
			t.Fatalf("round trip %+v -> %+v", p, got)
		}
	}
}
