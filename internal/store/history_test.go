package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func poll(server string, at time.Time, samples ...SensorSample) SensorPoll {
	return SensorPoll{ServerID: server, TS: at, Samples: samples}
}

func temp(id string, v float64) SensorSample {
	return SensorSample{Key: "temp:" + id, Kind: SensorTemp, Unit: UnitCelsius, Name: "CPU " + id, Value: v}
}

func mustInsert(t *testing.T, h HistoryRepository, p SensorPoll) InsertResult {
	t.Helper()
	res, err := h.Insert(context.Background(), p)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	return res
}

func keyID(t *testing.T, h HistoryReader, server, key string) int64 {
	t.Helper()
	keys, err := h.Keys(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Key == key {
			return k.ID
		}
	}
	t.Fatalf("key %s/%s not stored (%+v)", server, key, keys)
	return 0
}

func TestHistoryInsertCreatesAndUpdatesKeys(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	res := mustInsert(t, h, poll("r1", t0, temp("1", 40), temp("1", 41),
		SensorSample{Key: "power:consumed", Kind: SensorPower, Unit: UnitWatts, Name: "Draw", Value: 240},
		SensorSample{Key: "", Kind: SensorTemp, Unit: UnitCelsius, Value: 1},
		SensorSample{Key: "temp:nan", Kind: SensorTemp, Unit: UnitCelsius, Value: math.NaN()},
		SensorSample{Key: "temp:inf", Kind: SensorTemp, Unit: UnitCelsius, Value: math.Inf(1)},
		SensorSample{Key: "x:1", Kind: "bogus", Unit: UnitCelsius, Value: 1},
		SensorSample{Key: "x:2", Kind: SensorFan, Unit: "furlongs", Value: 1},
		SensorSample{Key: strings.Repeat("k", MaxSensorKeyLen+1), Kind: SensorFan, Unit: UnitRPM, Value: 1}))
	if res.Inserted != 2 || res.Behind {
		t.Fatalf("first poll = %+v; want 2 rows (the duplicate key and invalid samples skipped)", res)
	}
	long := strings.Repeat("é", MaxSensorNameLen) // 2 bytes a rune: capped on a rune boundary
	res = mustInsert(t, h, poll("r1", t0.Add(time.Minute),
		SensorSample{Key: "temp:1", Kind: SensorTemp, Unit: UnitCelsius, Name: long, Value: 42}))
	if res.Inserted != 1 || res.Behind {
		t.Fatalf("second poll = %+v", res)
	}
	keys, err := h.Keys(ctx, "r1")
	if err != nil || len(keys) != 2 {
		t.Fatalf("Keys = %+v, %v", keys, err)
	}
	k := keys[1] // ordered by kind: power, temp
	if k.Key != "temp:1" || k.Kind != SensorTemp || k.Unit != UnitCelsius || len(k.Name) != MaxSensorNameLen ||
		!k.First.Equal(t0) || !k.Last.Equal(t0.Add(time.Minute)) {
		t.Errorf("temp key = %+v", k)
	}
	if all, _ := h.Keys(ctx, ""); len(all) != 2 {
		t.Errorf("all keys = %d", len(all))
	}
	if _, err := h.Insert(ctx, poll("", t0)); !errors.Is(err, ErrInvalid) {
		t.Errorf("blank server: %v", err)
	}
}

func TestHistoryInsertDetectsClockGoingBack(t *testing.T) {
	h := newTestDB(t).History()
	mustInsert(t, h, poll("r1", t0, temp("1", 40)))
	if res := mustInsert(t, h, poll("r1", t0, temp("1", 99))); res.Inserted != 0 || res.Behind {
		t.Errorf("same timestamp again = %+v; want ignored, not behind", res)
	}
	if res := mustInsert(t, h, poll("r1", t0.Add(-time.Hour), temp("1", 39))); res.Inserted != 1 || !res.Behind {
		t.Errorf("older poll = %+v; want stored and behind", res)
	}
	keys, _ := h.Keys(context.Background(), "r1")
	if !keys[0].Last.Equal(t0) {
		t.Errorf("last_ts moved back to %v", keys[0].Last)
	}
	if res := mustInsert(t, h, poll("r1", t0.Add(-time.Hour), temp("2", 30))); res.Behind {
		t.Error("a new key is never behind")
	}
}

func seedMinutes(t *testing.T, h HistoryRepository, server string, from time.Time, n int, value func(i int) float64) {
	t.Helper()
	for i := 0; i < n; i++ {
		mustInsert(t, h, poll(server, from.Add(time.Duration(i)*time.Minute), temp("1", value(i))))
	}
}

func TestHistoryBucketsAndRollups(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	day := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	seedMinutes(t, h, "r1", day, 180, func(i int) float64 { return float64(i % 60) }) // 3 hours, 0..59 each
	id := keyID(t, h, "r1", "temp:1")

	raw, err := h.Buckets(ctx, id, TierRaw, day, day.Add(3*time.Hour), 30*time.Minute)
	if err != nil || len(raw) != 6 {
		t.Fatalf("raw buckets = %d, %v", len(raw), err)
	}
	if b := raw[1]; !b.Start.Equal(day.Add(30*time.Minute)) || b.Min != 30 || b.Max != 59 || b.N != 30 || b.Avg != 44.5 {
		t.Errorf("raw bucket 1 = %+v", b)
	}
	n, err := h.RollupHourly(ctx, day, day.Add(3*time.Hour))
	if err != nil || n != 3 {
		t.Fatalf("RollupHourly = %d, %v", n, err)
	}
	if n, err = h.RollupHourly(ctx, day, day.Add(3*time.Hour)); err != nil || n != 3 {
		t.Fatalf("RollupHourly again (idempotent) = %d, %v", n, err)
	}
	hourly, err := h.Buckets(ctx, id, TierHourly, day, day.Add(3*time.Hour), time.Hour)
	if err != nil || len(hourly) != 3 || hourly[2].Avg != 29.5 || hourly[2].N != 60 || hourly[2].Max != 59 {
		t.Fatalf("hourly = %+v, %v", hourly, err)
	}
	if _, err = h.RollupDaily(ctx, day, day.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	daily, err := h.Buckets(ctx, id, TierDaily, day, day.Add(24*time.Hour), 24*time.Hour)
	if err != nil || len(daily) != 1 || daily[0].N != 180 || daily[0].Avg != 29.5 || daily[0].Min != 0 {
		t.Fatalf("daily = %+v, %v", daily, err)
	}
	// Rollup rows aggregate further by their weights: three hours in one 3 h bucket.
	three, err := h.Buckets(ctx, id, TierHourly, day, day.Add(3*time.Hour), 3*time.Hour)
	if err != nil || len(three) != 1 || three[0].N != 180 || three[0].Avg != 29.5 {
		t.Fatalf("3 h from hourly = %+v, %v", three, err)
	}
	if first, ok, err := h.Earliest(ctx, id, TierHourly); err != nil || !ok || !first.Equal(day) {
		t.Errorf("Earliest hourly = %v %v %v", first, ok, err)
	}
	if _, ok, err := h.Earliest(ctx, 9999, TierDaily); err != nil || ok {
		t.Errorf("Earliest of an unknown key = %v %v", ok, err)
	}
}

func TestHistoryRejectsBadArguments(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	if _, err := h.RollupHourly(ctx, t0.Add(time.Minute), t0.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Errorf("unaligned hourly rollup: %v", err)
	}
	if _, err := h.RollupDaily(ctx, t0, t0.Add(time.Hour)); !errors.Is(err, ErrInvalid) { // t0 is noon
		t.Errorf("unaligned daily rollup: %v", err)
	}
	if _, err := h.Buckets(ctx, 1, TierRaw, t0, t0.Add(time.Hour), 1500*time.Millisecond); !errors.Is(err, ErrInvalid) {
		t.Errorf("fractional step: %v", err)
	}
	if _, err := h.Buckets(ctx, 1, "weekly", t0, t0.Add(time.Hour), time.Hour); err == nil {
		t.Error("unknown tier accepted")
	}
	if _, err := h.Raw(ctx, 1, t0, t0.Add(time.Hour), time.Time{}, MaxRawPage+1); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized page: %v", err)
	}
	if _, err := h.PruneBefore(ctx, 1, TierRaw, t0, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero batch: %v", err)
	}
	if _, err := h.PruneBefore(ctx, 1, "weekly", t0, 10); err == nil {
		t.Error("unknown tier pruned")
	}
	if _, err := h.KeepNewest(ctx, 1, 0, 10); !errors.Is(err, ErrInvalid) {
		t.Errorf("keep 0: %v", err)
	}
	if _, _, err := h.Earliest(ctx, 1, "weekly"); err == nil {
		t.Error("unknown tier earliest")
	}
}

func TestHistoryRawPaging(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	seedMinutes(t, h, "r1", t0, 25, func(i int) float64 { return float64(i) })
	id := keyID(t, h, "r1", "temp:1")
	var got []RawPoint
	after := time.Time{}
	for {
		page, err := h.Raw(ctx, id, t0, t0.Add(time.Hour), after, 10)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page...)
		if len(page) < 10 {
			break
		}
		after = page[len(page)-1].TS
	}
	if len(got) != 25 || got[24].Value != 24 || !got[0].TS.Equal(t0) {
		t.Fatalf("paged %d rows: %+v", len(got), got[len(got)-1])
	}
	if n, err := h.CountRaw(ctx, id, t0.Add(5*time.Minute), t0.Add(10*time.Minute)); err != nil || n != 5 {
		t.Errorf("CountRaw = %d, %v", n, err)
	}
}

func TestHistoryPrunes(t *testing.T) {
	db := newTestDB(t)
	h := db.History()
	ctx := context.Background()
	seedMinutes(t, h, "r1", t0, 20, func(i int) float64 { return float64(i) })
	id := keyID(t, h, "r1", "temp:1")
	n, err := h.PruneBefore(ctx, id, TierRaw, t0.Add(7*time.Minute), 3) // batches of 3: 3 + 3 + 1
	if err != nil || n != 7 {
		t.Fatalf("PruneBefore = %d, %v", n, err)
	}
	if n, err = h.KeepNewest(ctx, id, 10, 4); err != nil || n != 3 {
		t.Fatalf("KeepNewest = %d, %v; want the 3 oldest of 13 gone", n, err)
	}
	if n, err = h.KeepNewest(ctx, id, 10, 4); err != nil || n != 0 {
		t.Fatalf("KeepNewest again = %d, %v", n, err)
	}
	if first, _, _ := h.Earliest(ctx, id, TierRaw); !first.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("oldest kept = %v", first)
	}
	if _, err = h.RollupHourly(ctx, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err = h.DeleteIdleKeys(ctx, t0.Add(time.Hour)); err != nil || n != 0 {
		t.Errorf("a key with rows is not idle: %d, %v", n, err)
	}
	if err = h.DeleteKey(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	st, err := h.Stats(ctx)
	if err != nil || st.Keys != 0 || st.RawRows != 0 || st.HourlyRows != 0 || st.DBBytes <= 0 {
		t.Fatalf("after DeleteKey: %+v, %v", st, err)
	}
	mustInsert(t, h, poll("r2", t0, temp("9", 1)))
	id = keyID(t, h, "r2", "temp:9")
	if _, err = h.PruneBefore(ctx, id, TierRaw, t0.Add(time.Second), 100); err != nil {
		t.Fatal(err)
	}
	if n, err = h.DeleteIdleKeys(ctx, t0.Add(time.Second)); err != nil || n != 1 {
		t.Errorf("DeleteIdleKeys = %d, %v", n, err)
	}
}

func TestHistoryMetaAndStats(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	m, err := h.Meta(ctx)
	if err != nil || m.HourlyDone.UnixMilli() != 0 || !m.LastClockJump.IsZero() {
		t.Fatalf("fresh meta = %+v, %v", m, err)
	}
	day := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if err = h.SetWatermarks(ctx, day.Add(5*time.Hour), day); err != nil {
		t.Fatal(err)
	}
	if err = h.SetWatermarks(ctx, day.Add(time.Minute), day); !errors.Is(err, ErrInvalid) {
		t.Errorf("unaligned watermark: %v", err)
	}
	if err = h.NoteClockJump(ctx, t0); err != nil {
		t.Fatal(err)
	}
	m, _ = h.Meta(ctx)
	if !m.HourlyDone.Equal(day.Add(5*time.Hour)) || !m.DailyDone.Equal(day) || !m.LastClockJump.Equal(t0) ||
		!m.LastPassAt.IsZero() || !m.JanitorClock.IsZero() {
		t.Errorf("meta = %+v", m)
	}
	if err = h.SetPass(ctx, t0, t0.Add(-time.Hour), BootMark{ID: "b1", Uptime: 90 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err = h.NoteForwardJump(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if m, _ = h.Meta(ctx); !m.LastPassAt.Equal(t0) || !m.JanitorClock.Equal(t0.Add(-time.Hour)) || !m.LastForwardJump.Equal(t0) ||
		m.Boot != (BootMark{ID: "b1", Uptime: 90 * time.Second}) {
		t.Errorf("pass meta = %+v", m)
	}
	seedMinutes(t, h, "r1", t0, 3, func(int) float64 { return 1 })
	st, err := h.Stats(ctx)
	if err != nil || st.Keys != 1 || st.RawRows != 3 || st.DBBytes == 0 {
		t.Errorf("stats = %+v, %v", st, err)
	}
}

// TestHistoryQueriesUseThePrimaryKey: the rollups, bucket reads and prunes search
// sensor_raw by (key_id, ts), never by a full table scan (the table has no other index).
func TestHistoryQueriesUseThePrimaryKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`SELECT key_id, (ts / 3600000) * 3600000, MIN(value) FROM sensor_raw
			WHERE key_id IN (SELECT id FROM sensor_keys) AND ts >= 1 AND ts < 2 GROUP BY key_id, ts / 3600000`,
		`SELECT (ts / 60) * 60 AS b, MIN(value) FROM sensor_raw WHERE key_id = 1 AND ts >= 1 AND ts < 2 GROUP BY b`,
		`SELECT ts FROM sensor_raw WHERE key_id = 1 AND ts < 5 ORDER BY ts LIMIT 1 OFFSET 5000`,
		`SELECT ts FROM sensor_raw WHERE key_id = 1 ORDER BY ts DESC LIMIT 1 OFFSET 10`,
	} {
		rows, err := db.sql.QueryContext(ctx, `EXPLAIN QUERY PLAN `+q)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		_ = rows.Close()
		joined := strings.Join(plan, " | ")
		if !strings.Contains(joined, "SEARCH sensor_raw USING PRIMARY KEY (key_id=?") || strings.Contains(joined, "SCAN sensor_raw") {
			t.Errorf("plan of %q: %s", q, joined)
		}
	}
}

func TestHistoryInsertInsideATransaction(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	err := db.WithTx(ctx, func(tx *Tx) error {
		for i := 0; i < 3; i++ {
			if _, err := tx.History().Insert(ctx, poll("r1", t0.Add(time.Duration(i)*time.Minute), temp("1", 1))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := db.History().CountRaw(ctx, keyID(t, db.History(), "r1", "temp:1"), t0, t0.Add(time.Hour)); n != 3 {
		t.Errorf("rows %d", n)
	}
}

// TestHistoryKeysPerServerAreCapped: a BMC that invents sensor names cannot grow the
// keys table without bound: past MaxKeysPerServer new keys are refused (counted), known
// keys keep recording, and another server has its own budget.
func TestHistoryKeysPerServerAreCapped(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	var many []SensorSample
	for i := 0; i < MaxKeysPerServer+40; i++ {
		many = append(many, temp(fmt.Sprintf("hostile-%d", i), 1))
	}
	res := mustInsert(t, h, poll("r1", t0, many...))
	if res.Inserted != MaxKeysPerServer || res.Refused != 40 {
		t.Fatalf("first poll = %+v", res)
	}
	res = mustInsert(t, h, poll("r1", t0.Add(time.Minute), temp("hostile-0", 2), temp("brand-new", 3)))
	if res.Inserted != 1 || res.Refused != 1 {
		t.Fatalf("known key records, new one refused: %+v", res)
	}
	if res = mustInsert(t, h, poll("r2", t0, temp("1", 1))); res.Inserted != 1 || res.Refused != 0 {
		t.Fatalf("another server: %+v", res)
	}
	keys, _ := h.Keys(ctx, "r1")
	if len(keys) != MaxKeysPerServer {
		t.Fatalf("%d keys stored", len(keys))
	}
}

// TestHistoryUnitChangeStartsANewKey: a sensor whose unit or kind changes keeps its old
// rows under an archived key in the old unit; the readings in the new unit start a new
// key, so no series mixes units.
func TestHistoryUnitChangeStartsANewKey(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	fan := func(u SensorUnit, v float64) SensorSample {
		return SensorSample{Key: "fan:1", Kind: SensorFan, Unit: u, Name: "Fan 1", Value: v}
	}
	mustInsert(t, h, poll("r1", t0, fan(UnitRPM, 7000)))
	res := mustInsert(t, h, poll("r1", t0.Add(time.Minute), fan(UnitPercent, 40)))
	if res.Archived != 1 || res.Inserted != 1 {
		t.Fatalf("unit change = %+v", res)
	}
	keys, _ := h.Keys(ctx, "r1")
	if len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	cur, old := keys[0], keys[1]
	if cur.Key != "fan:1" {
		cur, old = old, cur
	}
	if cur.Unit != UnitPercent || !cur.First.Equal(t0.Add(time.Minute)) || old.Unit != UnitRPM ||
		!strings.HasPrefix(old.Key, "fan:1#rpm#") {
		t.Fatalf("current %+v, archived %+v", cur, old)
	}
	if n, _ := h.CountRaw(ctx, old.ID, t0, t0.Add(time.Hour)); n != 1 {
		t.Errorf("archived rows = %d", n)
	}
}

func TestHistoryFirstTSMovesBack(t *testing.T) {
	h := newTestDB(t).History()
	mustInsert(t, h, poll("r1", t0, temp("1", 1)))
	mustInsert(t, h, poll("r1", t0.Add(-time.Hour), temp("1", 1)))
	keys, _ := h.Keys(context.Background(), "r1")
	if !keys[0].First.Equal(t0.Add(-time.Hour)) || !keys[0].Last.Equal(t0) {
		t.Fatalf("key = %+v", keys[0])
	}
}

func fanAs(key string, u SensorUnit) SensorSample {
	return SensorSample{Key: key, Kind: SensorFan, Unit: u, Name: "Fan", Value: 1}
}

// TestUnitFlipsCannotExhaustTheKeyCap (re-check MEDIUM-N1, final MEDIUM): a fan flipping
// between RPM and percent on every one of 600 polls swaps between two keys: every
// reading is kept, nothing is deleted, and a real new sensor is still recorded.
func TestUnitFlipsCannotExhaustTheKeyCap(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	for i := 0; i < 600; i++ {
		u := UnitRPM
		if i%2 == 1 {
			u = UnitPercent
		}
		if res := mustInsert(t, h, poll("r1", t0.Add(time.Duration(i)*time.Minute), fanAs("fan:1", u))); res.Dropped != 0 {
			t.Fatalf("poll %d dropped an archive: %+v", i, res)
		}
	}
	keys, _ := h.Keys(ctx, "r1")
	if len(keys) != 2 {
		t.Fatalf("%d keys after 600 flips: %+v", len(keys), keys)
	}
	total := int64(0)
	for _, k := range keys {
		n, _ := h.CountRaw(ctx, k.ID, t0, t0.Add(24*time.Hour))
		total += n
		if k.Key == "fan:1" && k.Unit != UnitPercent {
			t.Errorf("the live key has the last unit: %+v", k)
		}
	}
	if total != 600 {
		t.Fatalf("%d readings kept, want 600", total)
	}
	if res := mustInsert(t, h, poll("r1", t0.Add(time.Hour*11), temp("real", 40))); res.Inserted != 1 || res.Refused != 0 {
		t.Fatalf("a real sensor after the flips: %+v", res)
	}
}

// TestArchivesAreBoundedPerSensor: a sensor that cycles through more unit and kind
// combinations than MaxArchivesPerKey keeps that many archives and reports what it
// dropped.
func TestArchivesAreBoundedPerSensor(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	combos := []SensorSample{fanAs("x:1", UnitRPM), fanAs("x:1", UnitPercent),
		{Key: "x:1", Kind: SensorTemp, Unit: UnitCelsius, Value: 1}, {Key: "x:1", Kind: SensorPower, Unit: UnitWatts, Value: 1},
		{Key: "x:1", Kind: SensorVolt, Unit: UnitVolts, Value: 1}, {Key: "x:1", Kind: SensorPSUIn, Unit: UnitWatts, Value: 1}}
	dropped := 0
	for i, c := range combos {
		dropped += mustInsert(t, h, poll("r1", t0.Add(time.Duration(i)*time.Minute), c)).Dropped
	}
	keys, _ := h.Keys(ctx, "r1")
	if len(keys) != 1+MaxArchivesPerKey || dropped != len(combos)-1-MaxArchivesPerKey {
		t.Fatalf("%d keys, %d dropped", len(keys), dropped)
	}
}

// TestArchivesMatchExactly (final LOW): a real sensor whose key contains "#" or shares a
// long prefix with another is never taken for that sensor's archive.
func TestArchivesMatchExactly(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	long := "fan:" + strings.Repeat("a", 140)
	mustInsert(t, h, poll("r1", t0, fanAs("fan:1", UnitRPM), fanAs("fan:1#rpm#7", UnitRPM), fanAs(long+"X", UnitRPM),
		fanAs(long+"Y", UnitRPM)))
	for i := 0; i < 6; i++ {
		u := UnitPercent
		if i%2 == 1 {
			u = UnitRPM
		}
		mustInsert(t, h, poll("r1", t0.Add(time.Duration(i+1)*time.Minute), fanAs("fan:1", u), fanAs(long+"X", u)))
	}
	keys, _ := h.Keys(ctx, "r1")
	names := map[string]bool{}
	for _, k := range keys {
		names[k.Key] = true
	}
	if !names["fan:1#rpm#7"] || !names[long+"Y"] || len(keys) != 6 {
		t.Fatalf("keys = %v", names)
	}
}

// TestNoArchiveWhenTheReplacementWouldBeRefused (re-check MEDIUM-N1c): at the cap, a unit
// change is refused instead of archiving a key whose replacement could not be stored.
func TestNoArchiveWhenTheReplacementWouldBeRefused(t *testing.T) {
	h := newTestDB(t).History()
	ctx := context.Background()
	var many []SensorSample
	for i := 0; i < MaxKeysPerServer-1; i++ {
		many = append(many, temp(fmt.Sprint(i), 1))
	}
	mustInsert(t, h, poll("r1", t0, append(many, fanAs("fan:1", UnitRPM))...))
	res := mustInsert(t, h, poll("r1", t0.Add(time.Minute), fanAs("fan:1", UnitPercent)))
	if res.Archived != 0 || res.Refused != 1 || res.Inserted != 0 {
		t.Fatalf("at the cap = %+v", res)
	}
	keys, _ := h.Keys(ctx, "r1")
	for _, k := range keys {
		if k.Key == "fan:1" && k.Unit != UnitRPM {
			t.Errorf("fan:1 relabelled: %+v", k)
		}
	}
}

// TestArchiveKeyCutOnARuneBoundary (re-check LOW-N4).
func TestArchiveKeyCutOnARuneBoundary(t *testing.T) {
	h := newTestDB(t).History()
	key := "fan:" + strings.Repeat("é", 78) // 160 bytes
	mustInsert(t, h, poll("r1", t0, fanAs(key, UnitRPM)))
	mustInsert(t, h, poll("r1", t0.Add(time.Minute), fanAs(key, UnitPercent)))
	keys, _ := h.Keys(context.Background(), "r1")
	for _, k := range keys {
		if !utf8.ValidString(k.Key) || len(k.Key) > MaxSensorKeyLen {
			t.Errorf("key %q", k.Key)
		}
	}
}
