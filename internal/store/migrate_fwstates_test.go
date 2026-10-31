package store

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// historySchema is the level before the firmware states fix (0015, the sensor history).
const historySchema = 15

// TestUpgradeSwapsFirmwareStates migrates a schema-0015 database written with the
// inverted Dell states (0014 took "Current-" for the running version): a row holding both
// gets running and the stored image swapped, its release date and document time cleared
// (they came from the stored image's member), the column is renamed to stored, and the
// "appeared" change row names the running version. Rows without a second state are
// untouched.
func TestUpgradeSwapsFirmwareStates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, historySchema)); err != nil {
		t.Fatalf("migrate to %d: %v", historySchema, err)
	}
	for _, q := range []string{
		`INSERT INTO firmware_components (server_id, component_id, fqdd, kind, name, named, running, previous, staged,
			lc_installed, release_date, updateable, identity, first_seen, last_seen, doc_read_at) VALUES
			('r1', '101434', '', 'enclosure', 'Backplane 0', 1, '2.25', '', '', '2.23', 5000, 1, '', 1000, 2000, 1500),
			('r1', '159', '', 'bios', 'BIOS', 1, '2.19.0', '2.18.1', '', '', 6000, 1, '', 1000, 2000, 1500),
			('r2', '101434', '', 'enclosure', 'Backplane 0', 1, '2.25', '', '', '2.23', NULL, 1, '', 1000, 2000, 1500)`,
		`INSERT INTO firmware_changes (server_id, component_id, fqdd, name, field, before, after, seen_at) VALUES
			('r1', '101434', '', 'Backplane 0', 'running', '', '2.25', 1000),
			('r1', '159', '', 'BIOS', 'running', '', '2.19.0', 1000),
			('r2', '101434', '', 'Backplane 0', 'running', '', '2.20', 900),
			('r2', '101434', '', 'Backplane 0', 'running', '2.20', '2.25', 1000)`,
	} {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	comps, err := db.Firmware().Components(ctx)
	if err != nil || len(comps) != 3 {
		t.Fatalf("components %+v, %v", comps, err)
	}
	for _, c := range comps {
		switch c.ServerID + "/" + c.ComponentID {
		case "r1/101434", "r2/101434":
			if c.Running != "2.23" || c.Stored != "2.25" || !c.ReleaseDate.IsZero() || !c.DocReadAt.IsZero() ||
				c.FirstSeen.UnixMilli() != 1000 || c.Name != "Backplane 0" {
				t.Errorf("swapped row %+v", c)
			}
		case "r1/159":
			if c.Running != "2.19.0" || c.Stored != "" || c.ReleaseDate.UnixMilli() != 6000 || c.DocReadAt.UnixMilli() != 1500 {
				t.Errorf("untouched row %+v", c)
			}
		default:
			t.Errorf("row %+v", c)
		}
	}
	r1, err := db.Firmware().Changes(ctx, "r1", 10)
	if err != nil || len(r1) != 2 {
		t.Fatalf("r1 changes %+v, %v", r1, err)
	}
	for _, ch := range r1 {
		if (ch.ComponentID == "101434" && ch.After != "2.23") || (ch.ComponentID == "159" && ch.After != "2.19.0") {
			t.Errorf("appeared row %+v", ch)
		}
	}
	// A real change row (before set) is history and stays as recorded, and so does an
	// "appeared" row that does not name the row's running version.
	r2, err := db.Firmware().Changes(ctx, "r2", 10)
	if err != nil || len(r2) != 2 || r2[0].After != "2.25" || r2[1].After != "2.20" {
		t.Fatalf("r2 changes %+v, %v", r2, err)
	}
	var cols []string
	rows, err := db.sql.QueryContext(ctx, `SELECT name FROM pragma_table_info('firmware_components')`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		if err = rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	_ = rows.Close()
	if !slices.Contains(cols, "stored") || slices.Contains(cols, "lc_installed") {
		t.Fatalf("columns %v", cols)
	}
	if _, err = db.sql.ExecContext(ctx, `UPDATE firmware_components SET stored = ? WHERE server_id = 'r1'`,
		strings.Repeat("9", 65)); err == nil {
		t.Fatal("the length CHECK did not follow the rename")
	}
	// Opening a database at head again applies nothing.
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if comps, err = again.Firmware().Components(ctx); err != nil || len(comps) != 3 || comps[0].Running != "2.23" {
		t.Fatalf("after reopen %+v, %v", comps, err)
	}
}
