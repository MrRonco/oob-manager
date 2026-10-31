package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNotifyTargets(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Notify()
	row := NotifyTargetRow{ID: "phone", Name: "Phone", Kind: "ntfy", URL: "https://ntfy.example.net/t", Enabled: true,
		OptionsJSON: `{}`, SubsJSON: `{"classes":[],"min_severity":"warning"}`, SecretVersion: 1,
		SecretEnc: []byte{1, 2, 3}, CreatedAt: t0, UpdatedAt: t0, UpdatedBy: "alice"}
	if err := r.PutTarget(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Name, row.CreatedAt, row.UpdatedAt = "Phone 2", t0.Add(time.Hour), t0.Add(time.Hour)
	if err := r.PutTarget(ctx, row); err != nil {
		t.Fatal(err)
	}
	got, terr := r.Targets(ctx)
	if terr != nil || len(got) != 1 || got[0].Name != "Phone 2" || !got[0].CreatedAt.Equal(t0) || !got[0].Enabled ||
		string(got[0].SecretEnc) != "\x01\x02\x03" {
		t.Fatalf("targets %+v %v", got, terr)
	}
	for _, bad := range []NotifyTargetRow{
		{ID: "BAD", Name: "x", Kind: "ntfy", URL: "u", OptionsJSON: "{}", SubsJSON: "{}", UpdatedBy: "a"},
		{ID: "x", Name: "x", Kind: "slack", URL: "u", OptionsJSON: "{}", SubsJSON: "{}", UpdatedBy: "a"},
		{ID: "x", Name: "x", Kind: "ntfy", URL: "u", OptionsJSON: "nope", SubsJSON: "{}", UpdatedBy: "a"},
	} {
		if err := r.PutTarget(ctx, bad); err == nil {
			t.Errorf("CHECK let %+v through", bad)
		}
	}
	if err := r.DeleteTarget(ctx, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteTarget(ctx, "phone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}
