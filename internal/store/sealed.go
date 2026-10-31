package store

import (
	"context"
	"database/sql"
	"fmt"
)

// sealedTables hold values sealed with the app keys (TOTP secrets, BMC credentials,
// notification secrets) or bound to them (API tokens). A database with a row in any of
// them must never be paired with newly generated keys (plan 09).
var sealedTables = []string{"users", "bmc_credentials", "notify_targets", "api_tokens"}

// HoldsSealedData reports whether any sealed table has a row.
func (d *DB) HoldsSealedData(ctx context.Context) (bool, error) { return holdsSealed(ctx, d.sql) }

// HoldsSealedData is the read-only form, for a check that must not migrate the file.
func (d *ReadDB) HoldsSealedData(ctx context.Context) (bool, error) { return holdsSealed(ctx, d.sql) }

func holdsSealed(ctx context.Context, db *sql.DB) (bool, error) {
	for _, t := range sealedTables {
		var one int
		// #nosec G202 -- table names come from the fixed list above.
		err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+t+`)`).Scan(&one)
		if err != nil {
			return false, fmt.Errorf("store: sealed data in %s: %w", t, err)
		}
		if one == 1 {
			return true, nil
		}
	}
	return false, nil
}
