package ui

import (
	"testing"

	"oob-manager/internal/store"
)

func TestAuditSentences(t *testing.T) {
	t.Parallel()
	names := map[string]string{"u1": "ana"}
	cases := []struct {
		rec  store.AuditRecord
		want string
	}{
		{store.AuditRecord{Principal: "admin", Action: "token.create", Result: "ok", ParamsJSON: `{"name":"dashboard","token_id":"t1"}`},
			"admin created API token dashboard"},
		{store.AuditRecord{Principal: "admin", Action: "admin.user.disable", Result: "ok", ParamsJSON: `{"target_id":"u1"}`},
			"admin disabled the account of ana"},
		{store.AuditRecord{Principal: "admin", Action: "admin.user.role", Result: "ok", ParamsJSON: `{"target_id":"zz","after":"operator"}`},
			"admin changed the role of a deleted or unknown user to operator"},
		{store.AuditRecord{Principal: "anonymous", Action: "auth.login", Result: "denied", ErrorClass: "password"},
			"Sign-in refused for an unknown user"},
		{store.AuditRecord{Principal: "ana", Action: "console.vnc.start", Result: "ok", ServerID: "srv-a"},
			"ana opened the graphical console of srv-a"},
		{store.AuditRecord{Principal: "ana", Action: "admin.users.manage", Result: "denied", ErrorClass: "stepup_required"},
			"ana was refused: manage users (step-up required)"},
		{store.AuditRecord{Principal: "system", Action: "app.start", Result: "ok"}, "oob-manager started"},
		{store.AuditRecord{Principal: "ana", Action: "something.new", Result: "ok"}, "ana: something.new"},
		{store.AuditRecord{Principal: "olga", Action: "server.firmware.rescan", Result: "error", ErrorClass: "paused", ServerID: "srv-a"},
			"olga asked for a firmware re-scan of srv-a (error (polling is paused))"},
		{store.AuditRecord{Principal: "system", Action: "server.firmware.changed", Result: "ok", ServerID: "srv-a",
			ParamsJSON: `{"component":"BIOS","field":"running","before":"2.19.0","after":"2.20.0"}`},
			"oob-manager recorded a firmware version change on srv-a"},
		{store.AuditRecord{Principal: "vera", Action: "server.firmware.rescan", Result: "denied", ErrorClass: "forbidden", ServerID: "srv-a"},
			"vera asked for a firmware re-scan of srv-a (denied (role does not allow it))"},
	}
	for _, c := range cases {
		if got := auditSentence(c.rec, names); got != c.want {
			t.Errorf("%s/%s = %q, want %q", c.rec.Action, c.rec.Result, got, c.want)
		}
	}
}

func TestAuditDetails(t *testing.T) {
	t.Parallel()
	got := auditDetails(`{"name":"dashboard","expires":"2027-01-19","n":3,"ok":true}`)
	want := []kv{{"expires", "2027-01-19"}, {"n", "3"}, {"name", "dashboard"}, {"ok", "true"}}
	if len(got) != len(want) {
		t.Fatalf("details = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("details = %+v, want %+v", got, want)
		}
	}
	if d := auditDetails(`not json`); len(d) != 1 || d[0].Key != "raw" {
		t.Fatalf("bad JSON = %+v", d)
	}
	if d := auditDetails(`{}`); len(d) != 0 {
		t.Fatalf("empty = %+v", d)
	}
}

func TestAuditSentenceSettingsChanges(t *testing.T) {
	t.Parallel()
	rec := store.AuditRecord{Principal: "morgan", Action: "admin.general.update", Result: "ok",
		ParamsJSON: `{"target":"general","rev":3,"changes":[{"field":"ui.time_zone","before":"UTC","after":"America/New_York"},{"field":"auth.session_idle","before":"30 min","after":"45 min"}]}`}
	want := "morgan changed the general settings: ui.time_zone UTC → America/New_York; auth.session_idle 30 min → 45 min"
	if got := auditSentence(rec, nil); got != want {
		t.Fatalf("sentence = %q", got)
	}
	for _, d := range auditDetails(rec.ParamsJSON) {
		if d.Key == "changes" {
			t.Fatal("changes repeated in the details")
		}
	}
	denied := store.AuditRecord{Principal: "morgan", Action: "admin.general.update", Result: "denied", ErrorClass: "locked",
		ParamsJSON: `{"target":"general"}`}
	if got := auditSentence(denied, nil); got != "morgan changed the general settings (denied (managed by config.yaml or locked))" {
		t.Fatalf("denied = %q", got)
	}
	prefs := store.AuditRecord{Principal: "victor", Action: "user.prefs.update", Result: "ok",
		ParamsJSON: `{"target":"self","changes":[{"field":"theme","before":"default","after":"nord"}]}`}
	if got := auditSentence(prefs, nil); got != "victor changed their display preferences: theme default → nord" {
		t.Fatalf("prefs = %q", got)
	}
}
