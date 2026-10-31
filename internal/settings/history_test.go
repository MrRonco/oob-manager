package settings

import (
	"context"
	"errors"
	"strings"
	"testing"

	"oob-manager/internal/config"
)

// TestUpdateHistorySettings: the History group saves like the other General keys
// (days as whole numbers, switches as on/off), audits old → new with units and is read
// back by Resolve; the cross-tier rule is enforced with the file validator.
func TestUpdateHistorySettings(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	changes, err := f.svc.UpdateGeneral(ctx, f.actor, 0, map[string]string{config.KeyHistoryRawDays: "3",
		config.KeyHistorySampleVoltages: "off", config.KeyHistorySamplePSUs: "on"})
	if err != nil || len(changes) != 2 {
		t.Fatalf("changes = %+v, %v", changes, err)
	}
	g := f.svc.Current().General
	if g.HistoryRawDays != 3 || g.SampleVoltages || !g.SamplePSUs {
		t.Fatalf("General = %+v", g)
	}
	rows := f.auditRows(t, ActionGeneralUpdate)
	if len(rows) != 1 || !strings.Contains(rows[0].ParamsJSON, `"7 d"`) || !strings.Contains(rows[0].ParamsJSON, `"3 d"`) ||
		!strings.Contains(rows[0].ParamsJSON, `"off"`) {
		t.Errorf("audit = %+v", rows)
	}
	fld, ok := f.svc.Current().Field(config.KeyHistorySampleVoltages)
	if !ok || fld.Value != "off" || fld.Source != SourceDB || fld.Default != "on" {
		t.Errorf("field = %+v", fld)
	}
	if _, err = f.svc.UpdateGeneral(ctx, f.actor, 1, map[string]string{config.KeyHistoryHourlyDays: "2"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("hourly below its minimum: %v", err)
	}
	if _, err = f.svc.UpdateGeneral(ctx, f.actor, 1, map[string]string{config.KeyHistoryRawDays: "20",
		config.KeyHistoryHourlyDays: "10"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("hourly shorter than raw: %v", err)
	}
	if _, err = f.svc.UpdateGeneral(ctx, f.actor, 1, map[string]string{config.KeyHistorySamplePSUs: "maybe"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("switch not on/off: %v", err)
	}
	if len(HistoryKeys()) != 5 {
		t.Errorf("HistoryKeys = %v", HistoryKeys())
	}
}

func TestHistoryFileKeysWin(t *testing.T) {
	f := newFixture(t, "history: { raw_days: 2, sample_psus: false }\n")
	if _, err := f.svc.UpdateGeneral(context.Background(), f.actor, 0, map[string]string{config.KeyHistoryRawDays: "5"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("file-managed key changed: %v", err)
	}
	fld, _ := f.svc.Current().Field(config.KeyHistorySamplePSUs)
	if !fld.FileManaged() || fld.Value != "off" {
		t.Errorf("field = %+v", fld)
	}
}
