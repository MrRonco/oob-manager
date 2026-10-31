package main

import (
	"context"
	"strings"
	"testing"

	"oob-manager/internal/store"
)

// TestAdminRecover: the break-glass CLI re-enables and promotes an account (drill 8).
func TestAdminRecover(t *testing.T) {
	d, _ := bootstrapped(t)
	db, err := store.Open(context.Background(), d.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.Users().ByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Users().SetDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	if err = db.Users().SetRole(context.Background(), u.ID, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Without -yes and without the typed confirmation nothing changes.
	if rc, _, _ := runCLI(t, "admin-recover", "-config", d.configPath, "-username", "admin"); rc == 0 {
		t.Fatal("admin-recover ran without a confirmation")
	}
	rc, out, errOut := runCLI(t, "admin-recover", "-config", d.configPath, "-username", "admin", "-yes")
	if rc != 0 || !strings.Contains(out, `"admin" is an enabled admin again`) ||
		!strings.Contains(out, "currently: role viewer, disabled") {
		t.Fatalf("admin-recover: %d\n%s%s", rc, out, errOut)
	}
	db, err = store.Open(context.Background(), d.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, _ = db.Users().ByUsername(context.Background(), "admin")
	if u.Disabled || u.Role != store.RoleAdmin {
		t.Fatalf("after recover: %+v", u)
	}
	if rc, _, _ := runCLI(t, "admin-recover", "-config", d.configPath, "-username", "nobody", "-yes"); rc == 0 {
		t.Fatal("unknown user recovered")
	}
	// An invalid name is refused before anything is written to the audit log.
	before := auditCount(t, d.dbPath)
	if rc, _, _ := runCLI(t, "admin-recover", "-config", d.configPath, "-username", "bad name!", "-yes"); rc == 0 {
		t.Fatal("invalid username accepted")
	}
	if after := auditCount(t, d.dbPath); after != before {
		t.Fatalf("invalid username wrote %d audit rows", after-before)
	}
	if rc, _, _ := runCLI(t, "admin-recover", "-config", d.configPath); rc == 0 {
		t.Fatal("missing -username accepted")
	}
}

// TestAdminRecoverInteractiveConfirm: typing the username back confirms; anything else aborts.
func TestAdminRecoverInteractiveConfirm(t *testing.T) {
	d, _ := bootstrapped(t)
	var out, errOut syncBuffer
	rc := run([]string{"oob-manager", "admin-recover", "-config", d.configPath, "-username", "admin"},
		cliEnv(context.Background(), strings.NewReader("someone-else\n"), &out, &errOut))
	if rc == 0 {
		t.Fatal("a wrong confirmation was accepted")
	}
	var out2, errOut2 syncBuffer
	rc = run([]string{"oob-manager", "admin-recover", "-config", d.configPath, "-username", "admin"},
		cliEnv(context.Background(), strings.NewReader("admin\n"), &out2, &errOut2))
	if rc != 0 || !strings.Contains(out2.String(), "enabled admin again") {
		t.Fatalf("typed confirmation: %d %s %s", rc, out2.String(), errOut2.String())
	}
}

func auditCount(t *testing.T, dbPath string) int64 {
	t.Helper()
	db, err := store.OpenReadOnly(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Audit().List(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(rows))
}
