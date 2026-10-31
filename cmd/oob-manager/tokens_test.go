package main

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/auth"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

var tokenLine = regexp.MustCompile(`^oobk_[A-Za-z0-9_-]{43}\n$`)

// bootstrapped returns a deployment whose admin account "admin" is enrolled and confirmed,
// plus the admin's TOTP secret.
func bootstrapped(t *testing.T) (deployment, string) {
	t.Helper()
	d := newDeployment(t, "")
	return d, bootstrapIn(t, d, func(*env) {})
}

// bootstrapIn runs bootstrap-admin for "admin" in d (tweak adjusts the env, e.g. the GELF
// dial hook) and returns the admin's TOTP secret.
func bootstrapIn(t *testing.T, d deployment, tweak func(*env)) string {
	t.Helper()
	inR, inW := io.Pipe()
	var out, errOut syncBuffer
	done := make(chan int, 1)
	e := cliEnv(context.Background(), inR, &out, &errOut)
	tweak(&e)
	go func() {
		done <- run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "admin"}, e)
	}()
	go func() { _, _ = io.WriteString(inW, adminPassword+"\n"+adminPassword+"\n") }()
	waitUntil(t, "enrollment printed", func() bool { return secretLine.MatchString(out.String()) })
	secret := secretLine.FindStringSubmatch(out.String())[1]
	// The code for the CURRENT step stays valid if a 30 s boundary passes before the CLI
	// checks it (one step of skew). A code for the previous step did not: it hung the
	// package whenever the boundary fell between GenerateCode and the check.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Close stdin after the one code: a rejected code then ends the CLI ("input closed")
	// instead of leaving it blocked on a second prompt.
	go func() { _, _ = io.WriteString(inW, code+"\n"); _ = inW.Close() }()
	if rc := awaitExit(t, done); rc != 0 {
		t.Fatalf("bootstrap: %d %s", rc, errOut.String())
	}
	return secret
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	rc := run(append([]string{"oob-manager"}, args...), cliEnv(context.Background(), strings.NewReader(""), &out, &errOut))
	return rc, out.String(), errOut.String()
}

func verifyToken(t *testing.T, dbPath, raw string) error {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ts, err := auth.NewTokenService(authrepo.New(db).Tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ts.Verify(context.Background(), raw)
	return err
}

func TestTokenCreateListRevoke(t *testing.T) {
	d, _ := bootstrapped(t)
	rc, out, errOut := runCLI(t, "token", "create", "--config", d.configPath, "--name", "dashboard", "--expires", "90d")
	if rc != 0 || !tokenLine.MatchString(out) {
		t.Fatalf("create: %d out %q err %q", rc, out, errOut)
	}
	raw := strings.TrimSpace(out)
	if strings.Contains(errOut, raw) {
		t.Fatal("token printed to stderr")
	}
	if err := verifyToken(t, d.dbPath, raw); err != nil {
		t.Fatalf("CLI token rejected: %v", err)
	}
	id := regexp.MustCompile(`Token ([0-9a-f]+) `).FindStringSubmatch(errOut)[1]

	rc, out, _ = runCLI(t, "token", "list", "--config", d.configPath)
	if rc != 0 || !strings.Contains(out, id) || !strings.Contains(out, "dashboard") || !strings.Contains(out, "active") ||
		strings.Contains(out, raw) || strings.Contains(out, "never  ") {
		t.Fatalf("list: %d %q", rc, out)
	}
	if want := time.Now().Add(90 * 24 * time.Hour).UTC().Format("2006-01-02"); !strings.Contains(out, want) {
		t.Fatalf("list lacks expiry %s: %q", want, out)
	}

	if rc, out, _ = runCLI(t, "token", "revoke", id, "--config", d.configPath); rc != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %d %q", rc, out)
	}
	if err := verifyToken(t, d.dbPath, raw); err == nil {
		t.Fatal("revoked token still verifies")
	}
	if rc, _, errOut = runCLI(t, "token", "revoke", "--config", d.configPath, id); rc != 1 || !strings.Contains(errOut, "no unrevoked token") {
		t.Fatalf("second revoke: %d %q", rc, errOut)
	}
	if rc, out, _ = runCLI(t, "token", "list", "--config", d.configPath); rc != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("list after revoke: %q", out)
	}
	assertAudited(t, d.dbPath, "token.create", "token.revoke")
}

func TestTokenCreateNeverExpiresAndOwner(t *testing.T) {
	d, _ := bootstrapped(t)
	rc, out, errOut := runCLI(t, "token", "create", "-config", d.configPath, "-name", "kuma", "-owner", "admin")
	if rc != 0 || !tokenLine.MatchString(out) || !strings.Contains(errOut, "expires never") {
		t.Fatalf("create: %d %q %q", rc, out, errOut)
	}
	if rc, _, errOut = runCLI(t, "token", "create", "-config", d.configPath, "-name", "x", "-owner", "ghost"); rc != 1 ||
		!strings.Contains(errOut, "no such user") {
		t.Fatalf("unknown owner: %d %q", rc, errOut)
	}
}

func TestTokenCommandErrors(t *testing.T) {
	d := newDeployment(t, "") // no admin yet
	cases := map[string]struct {
		args []string
		want string
	}{
		"no sub":       {[]string{"token"}, "create, list or revoke"},
		"bad sub":      {[]string{"token", "mint"}, "unknown subcommand"},
		"no name":      {[]string{"token", "create", "-config", d.configPath}, "--name is required"},
		"bad expiry":   {[]string{"token", "create", "-config", d.configPath, "-name", "x", "-expires", "soon"}, "--expires"},
		"zero days":    {[]string{"token", "create", "-config", d.configPath, "-name", "x", "-expires", "0d"}, "positive"},
		"too long":     {[]string{"token", "create", "-config", d.configPath, "-name", "x", "-expires", "9999d"}, "lifetime"},
		"no admin":     {[]string{"token", "create", "-config", d.configPath, "-name", "x"}, "0 active admins"},
		"extra arg":    {[]string{"token", "create", "-config", d.configPath, "-name", "x", "y"}, "expected 0"},
		"list extra":   {[]string{"token", "list", "-config", d.configPath, "y"}, "expected 0"},
		"revoke no id": {[]string{"token", "revoke", "-config", d.configPath}, "token revoke <id>"},
		"bad flag":     {[]string{"token", "list", "-nope"}, "flag provided but not defined"},
		"bad config":   {[]string{"token", "list", "-config", d.dir + "/missing.yaml"}, "missing.yaml"},
	}
	for name, c := range cases {
		if rc, _, errOut := runCLI(t, c.args...); rc == 0 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d stderr %q", name, rc, errOut)
		}
	}
	if rc, out, errOut := runCLI(t, "token", "list", "-config", d.configPath); rc != 0 || out != "" ||
		!strings.Contains(errOut, "No API tokens") {
		t.Fatalf("empty list: %d %q %q", rc, out, errOut)
	}
}

func TestParseLifetime(t *testing.T) {
	cases := map[string]time.Duration{"": 0, "never": 0, "90d": 90 * 24 * time.Hour, "720h": 720 * time.Hour, " 1d ": 24 * time.Hour}
	for in, want := range cases {
		if got, err := parseLifetime(in); err != nil || got != want {
			t.Errorf("parseLifetime(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"-1d", "xd", "-5h", "0s", "forever"} {
		if _, err := parseLifetime(bad); err == nil {
			t.Errorf("parseLifetime(%q) accepted", bad)
		}
	}
}
