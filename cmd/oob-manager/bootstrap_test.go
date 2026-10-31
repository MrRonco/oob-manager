package main

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

const adminPassword = "correct horse battery staple"

var secretLine = regexp.MustCompile(`Secret: ([A-Z2-7]+)`)

func TestBootstrapAdminEndToEnd(t *testing.T) {
	d := newDeployment(t, "")
	inR, inW := io.Pipe()
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), inR, &out, &errOut)
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "morgan"}, e)
	}()
	if _, err := io.WriteString(inW, adminPassword+"\n"+adminPassword+"\n"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "enrollment printed", func() bool { return secretLine.MatchString(out.String()) })
	secret := secretLine.FindStringSubmatch(out.String())[1]
	if !strings.Contains(out.String(), "otpauth://totp/") || strings.Count(out.String(), secret) != 2 {
		t.Fatalf("enrollment output %q", out.String())
	}
	// One wrong code, then the right one.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(inW, "000000\n"+code+"\n"); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close() // a rejected code ends the CLI instead of blocking on another prompt
	if rc := awaitExit(t, done); rc != 0 || !strings.Contains(out.String(), "TOTP confirmed") {
		t.Fatalf("exit %d out %q err %q", rc, out.String(), errOut.String())
	}
	if strings.Contains(errOut.String(), adminPassword) || strings.Contains(errOut.String(), secret) {
		t.Fatal("password or TOTP secret reached stderr")
	}
	assertAudited(t, d.dbPath, "admin.bootstrap", "admin.totp_confirmed")

	db, err := store.Open(context.Background(), d.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.Users().ByUsername(context.Background(), "morgan")
	_ = db.Close()
	if err != nil || u.Role != store.RoleAdmin || !u.TOTPConfirmed {
		t.Fatalf("stored admin %+v err %v", u, err)
	}

	// A second bootstrap is refused once any user exists.
	again := cliEnv(context.Background(), strings.NewReader(adminPassword+"\n"+adminPassword+"\n"), &out, &errOut)
	if rc := run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "other"}, again); rc != 1 ||
		!strings.Contains(errOut.String(), "already exist") {
		t.Fatalf("second bootstrap: %d %q", rc, errOut.String())
	}
}

func TestBootstrapInputErrors(t *testing.T) {
	d := newDeployment(t, "")
	args := []string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "morgan"}
	cases := map[string]struct {
		input string
		tty   bool
		want  string
	}{
		"no terminal": {input: adminPassword + "\n", want: "interactive terminal"},
		"too short":   {input: "short\n", tty: true, want: "password"},
		"mismatch":    {input: adminPassword + "\n" + adminPassword + "x\n", tty: true, want: "do not match"},
		"eof":         {input: "", tty: true, want: "input closed"},
		"eof repeat":  {input: adminPassword + "\n", tty: true, want: "input closed"},
	}
	for name, c := range cases {
		var out, errOut syncBuffer
		e := cliEnv(context.Background(), strings.NewReader(c.input), &out, &errOut)
		if !c.tty {
			e.noEcho = func() (func(), error) { return nil, errNotTerminal }
		}
		if rc := run(args, e); rc != 1 || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%s: exit %d stderr %q", name, rc, errOut.String())
		}
	}
	var out, errOut syncBuffer
	if rc := run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath}, cliEnv(context.Background(),
		strings.NewReader(""), &out, &errOut)); rc != 1 || !strings.Contains(errOut.String(), "-username") {
		t.Fatalf("missing username: %d %q", rc, errOut.String())
	}
}

func TestBootstrapConfirmGivesUpAndConfirmTOTPRetries(t *testing.T) {
	d := newDeployment(t, "")
	var out, errOut syncBuffer
	in := adminPassword + "\n" + adminPassword + "\n111111\n222222\n333333\n"
	e := cliEnv(context.Background(), strings.NewReader(in), &out, &errOut)
	rc := run([]string{"oob-manager", "bootstrap-admin", "-config", d.configPath, "-username", "morgan"}, e)
	if rc != 1 || !strings.Contains(errOut.String(), "confirm-totp -username morgan") {
		t.Fatalf("exit %d stderr %q", rc, errOut.String())
	}
	secret := secretLine.FindStringSubmatch(out.String())[1]
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out2, err2 := syncBuffer{}, syncBuffer{}
	e = cliEnv(context.Background(), strings.NewReader(adminPassword+"\n"+code+"\n"), &out2, &err2)
	if rc := run([]string{"oob-manager", "confirm-totp", "-config", d.configPath, "-username", "morgan"}, e); rc != 0 {
		t.Fatalf("confirm-totp exit %d: %q", rc, err2.String())
	}
	e = cliEnv(context.Background(), strings.NewReader(""), &out2, &err2)
	if rc := run([]string{"oob-manager", "confirm-totp", "-config", d.configPath, "-username", "morgan"}, e); rc != 1 {
		t.Fatal("confirm-totp without input must fail")
	}
}

func TestGenAppKeys(t *testing.T) {
	var out, errOut syncBuffer
	if rc := run([]string{"oob-manager", "gen-app-keys"}, cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	if _, err := secrets.ParseAppKeys([]byte(out.String())); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
}

func TestNewBMCDriverSelectsByKind(t *testing.T) {
	cred := secrets.Credential{Username: "oob_ro", Password: secrets.New("pw")}
	s := config.Server{ID: "x", BMC: config.BMCConfig{Address: "192.0.2.70", Kind: config.KindIDRAC8}, TLSPinSHA256: testPin}
	if d, err := newBMCDriver(s, cred); err != nil {
		t.Fatal(err)
	} else if _, ok := d.(*dellredfish.Driver); !ok {
		t.Fatalf("idrac8 driver %T", d)
	}
	s.BMC.Kind = config.KindRedfish
	s.BMC.Address = "fd00::1"
	if d, err := newBMCDriver(s, cred); err != nil {
		t.Fatal(err)
	} else if _, ok := d.(*redfish.Driver); !ok {
		t.Fatalf("redfish driver %T", d)
	}
	s.BMC.Kind = config.KindIPMI
	if _, err := newBMCDriver(s, cred); !errors.Is(err, errNoDriver) {
		t.Fatalf("ipmi: %v", err)
	}
}

func TestSweepDeletesExpiredRows(t *testing.T) {
	d := newDeployment(t, "")
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	var errOut syncBuffer
	c, err := openCore(context.Background(), cfg, newLogger(&errOut, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	ctx := context.Background()
	now := time.Now()
	if _, err := c.db.Lockouts().RecordFailure(ctx, "ip:1", now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Lockouts().RecordFailure(ctx, "ip:2", now); err != nil {
		t.Fatal(err)
	}
	sweep(ctx, c, now)
	if st, _ := c.db.Lockouts().Get(ctx, "ip:1"); st.Failures != 0 {
		t.Fatal("old lockout row kept")
	}
	if st, _ := c.db.Lockouts().Get(ctx, "ip:2"); st.Failures != 1 {
		t.Fatal("fresh lockout row removed")
	}
	jctx, cancel := context.WithCancel(ctx)
	cancel()
	janitor(jctx, c, time.Hour) // returns at once on a cancelled context
}
