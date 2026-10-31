package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/store"
)

func addSession(t *testing.T, dbPath, username string) []byte {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, err := db.Users().ByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	h := []byte("session-hash-for-test-0123456789")
	now := time.Now()
	if err := db.Sessions().Create(ctx, store.Session{IDHash: h, UserID: u.ID, Level: store.SessionFull,
		CreatedAt: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	return h
}

func sessionExists(t *testing.T, dbPath string, h []byte) bool {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Sessions().Get(context.Background(), h)
	return err == nil
}

func confirmWith(t *testing.T, configPath, secret string, at time.Time) (int, string) {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(adminPassword+"\n"+code+"\n"), &out, &errOut)
	rc := run([]string{"oob-manager", "confirm-totp", "-config", configPath, "-username", "admin"}, e)
	return rc, out.String() + errOut.String()
}

func TestResetTOTP(t *testing.T) {
	d, oldSecret := bootstrapped(t)
	sess := addSession(t, d.dbPath, "admin")

	rc, out, errOut := runCLI(t, "reset-totp", "--config", d.configPath, "--user", "admin")
	if rc != 0 || !secretLine.MatchString(out) || !strings.Contains(out, "otpauth://totp/") {
		t.Fatalf("reset: %d out %q err %q", rc, out, errOut)
	}
	newSecret := secretLine.FindStringSubmatch(out)[1]
	if newSecret == oldSecret || strings.Count(out, newSecret) != 2 || strings.Contains(errOut, newSecret) {
		t.Fatalf("secret handling: %q / %q", out, errOut)
	}
	if sessionExists(t, d.dbPath, sess) {
		t.Fatal("session survived reset-totp")
	}
	assertAudited(t, d.dbPath, "admin.totp_reset")

	if rc, msg := confirmWith(t, d.configPath, oldSecret, time.Now()); rc == 0 {
		t.Fatalf("old secret confirmed the reset: %s", msg)
	}
	if rc, msg := confirmWith(t, d.configPath, newSecret, time.Now()); rc != 0 {
		t.Fatalf("confirm with new secret: %s", msg)
	}
}

func TestResetTOTPErrors(t *testing.T) {
	d, _ := bootstrapped(t)
	cases := map[string]struct {
		args []string
		want string
	}{
		"no user":    {[]string{"reset-totp", "-config", d.configPath}, "--user is required"},
		"unknown":    {[]string{"reset-totp", "-config", d.configPath, "-user", "ghost"}, "not found"},
		"bad name":   {[]string{"reset-totp", "-config", d.configPath, "-user", "Bad Name"}, "username must match"},
		"extra":      {[]string{"reset-totp", "-config", d.configPath, "-user", "admin", "x"}, "expected 0"},
		"bad flag":   {[]string{"reset-totp", "-x"}, "not defined"},
		"bad config": {[]string{"reset-totp", "-config", d.dir + "/nope.yaml", "-user", "admin"}, "nope.yaml"},
	}
	for name, c := range cases {
		if rc, _, errOut := runCLI(t, c.args...); rc != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d stderr %q", name, rc, errOut)
		}
	}
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
	e.stdoutTTY = func() bool { return false }
	if rc := run([]string{"oob-manager", "reset-totp", "-config", d.configPath, "-user", "admin"}, e); rc != 1 ||
		!strings.Contains(errOut.String(), "terminal") || out.String() != "" {
		t.Fatalf("no tty: %d %q %q", rc, out.String(), errOut.String())
	}
}
