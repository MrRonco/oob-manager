package redfish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

const idrac8SEL = "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel"

func TestEventLogIDRAC9(t *testing.T) {
	s := mockFor(t, idrac9)
	log, err := driverFor(t, s).EventLog(testCtx(t), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if log.Len() != 1 || !log.Complete() || !strings.HasSuffix(log.Source(), "/LogServices/Sel/Entries") {
		t.Fatalf("log: len %d complete %v src %s", log.Len(), log.Complete(), log.Source())
	}
	e := log.Entries()[0]
	want := time.Date(2023, 5, 24, 8, 29, 19, 0, time.UTC)
	if e.ID != "1" || e.Message != "Log cleared." || e.Severity != bmc.SeverityOK || !e.Created.Equal(want) ||
		e.EntryCode != "Assert" || e.SensorType != "Event Logging Disabled" || e.EntryType != "SEL" || e.MessageID != "6f02ffff" {
		t.Fatalf("entry %+v", e)
	}
	assertNoWrites(t, s)
}

func TestEventLogIDRAC8LegacyPathAndQuirks(t *testing.T) {
	s := mockFor(t, idrac8)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if log.Source() != idrac8SEL || log.Len() != 15 {
		t.Fatalf("src %s len %d", log.Source(), log.Len())
	}
	// Members@odata.count says 85 but only 15 are present and nextLink is empty.
	if log.Complete() {
		t.Fatal("log with fewer members than Members@odata.count must be incomplete")
	}
	es := log.Entries()
	if es[0].ID != "85" || es[0].EntryCode != "Deassert" || es[0].SensorType != "Physical Chassis Security" {
		t.Fatalf("first entry (iDRAC8 array-of-Member quirk) %+v", es[0])
	}
	if es[1].Severity != bmc.SeverityCritical || es[1].Message != "The chassis is open while the power is off." {
		t.Fatalf("second entry %+v", es[1])
	}
}

func TestEventLogSinceFilter(t *testing.T) {
	s := mockFor(t, idrac8)
	since := time.Date(2024, 12, 18, 9, 0, 0, 0, time.UTC)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), since)
	if err != nil {
		t.Fatal(err)
	}
	if log.Len() != 2 || log.Entries()[0].ID != "83" || log.Entries()[1].ID != "82" {
		t.Fatalf("filtered entries %+v", log.Entries())
	}
}

func TestEventLogUnsupportedWithoutSEL(t *testing.T) {
	s := mockFor(t, idrac8)
	_, err := driverFor(t, s).EventLog(testCtx(t), time.Time{})
	if !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestEventLogPaging(t *testing.T) {
	const page2 = idrac8SEL + "/page2"
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(idrac8SEL, `{"Members":[
			{"Id":"3","Created":"2026-10-20T10:00:00Z","Severity":"Warning","Message":"a"}],
			"Members@odata.count":2,"Members@odata.nextLink":"`+page2+`"}`),
		redfishmock.WithOverlay(page2, `{"Members":[
			{"Id":"2","Created":"bogus","Severity":"OK","Message":"b","EntryCode":null}],
			"Members@odata.count":2}`),
	)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if log.Len() != 2 || !log.Complete() || !log.Entries()[1].Created.IsZero() {
		t.Fatalf("paging: %+v complete=%v", log.Entries(), log.Complete())
	}
}

func TestEventLogBrokenNextPageIsIncomplete(t *testing.T) {
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(idrac8SEL, `{"Members":[{"Id":"3","Message":"a"}],
			"Members@odata.nextLink":"/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel/gone"}`),
	)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), time.Time{})
	if err != nil || log.Len() != 1 || log.Complete() {
		t.Fatalf("err %v len %d complete %v", err, log.Len(), log.Complete())
	}
}

func TestEventLogUnsafeNextLinkIsNotFollowed(t *testing.T) {
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(idrac8SEL, `{"Members":[{"Id":"3","Message":"a"}],
			"Members@odata.nextLink":"https://evil.example/redfish/v1/x"}`),
	)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), time.Time{})
	if err != nil || log.Complete() {
		t.Fatalf("err %v complete %v", err, log.Complete())
	}
}

func TestEventLogLongMessagesAreTruncated(t *testing.T) {
	long := strings.Repeat("x", 5000)
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(idrac8SEL, `{"Members":[{"Id":"1","Message":"`+long+`","SensorType":[{"Member":"a"},{"Member":"b"}]}]}`),
	)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	e := log.Entries()[0]
	if len(e.Message) > maxFieldLen || e.SensorType != "a, b" {
		t.Fatalf("len %d sensor %q", len(e.Message), e.SensorType)
	}
}

func TestReadLogDecodeError(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithOverlay(idrac8SEL, `{"Members":"nope"}`))
	_, err := driverFor(t, s).ReadLog(testCtx(t), idrac8SEL, time.Time{})
	if !errors.Is(err, bmc.ErrDecode) {
		t.Fatalf("want ErrDecode, got %v", err)
	}
}

func TestEventLogSinceWithAscendingOrderReadsAllPages(t *testing.T) {
	const page2 = idrac8SEL + "/page2"
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(idrac8SEL, `{"Members":[
			{"Id":"1","Created":"2026-01-01T00:00:00Z","Message":"old"}],
			"Members@odata.count":2,"Members@odata.nextLink":"`+page2+`"}`),
		redfishmock.WithOverlay(page2, `{"Members":[
			{"Id":"2","Created":"2026-10-20T00:00:00Z","Message":"new"}],"Members@odata.count":2}`),
	)
	since := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	log, err := driverFor(t, s, WithSELFallbacks(dellSEL)).EventLog(testCtx(t), since)
	if err != nil || log.Len() != 1 || log.Entries()[0].ID != "2" || !log.Complete() {
		t.Fatalf("err %v entries %+v complete %v", err, log.Entries(), log.Complete())
	}
}
