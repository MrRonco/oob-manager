package ui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
)

// victorPage creates and enrols victor and returns his settings page path.
func victorPage(t *testing.T, e *settingsEnv, c *client) string {
	t.Helper()
	e.enrolViaLink(createVictor(t, c, "viewer"), testPassword)
	m := userIDRE.FindStringSubmatch(c.get("/settings/users").Body.String())
	if m == nil {
		t.Fatal("no user link")
	}
	return "/settings/users/" + m[1]
}

func TestDisableAccountGoesThroughAConfirmPage(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	result(c.get(userPage)).contains(t, `href="`+userPage+`/disable"`, "Disable account…").lacks(t, `action="`+userPage+`/disable"`)
	page := result(c.get(userPage+"/disable")).status(t, http.StatusOK).
		contains(t, "<h1>Disable account victor?</h1>", "What happens", "Reversible",
			`href="`+userPage+`" autofocus>Cancel</a>`, `name="confirm" value="yes"`, "Disable victor",
			"Step-up fresh until").
		lacks(t, `name="typed"`, `name="code"`)
	// A POST without the confirm page's field is sent back to the confirm page.
	result(c.do(http.MethodPost, userPage+"/disable", url.Values{csrfField: {csrfForAny(t, page.rec.Body.String(), userPage+"/disable")}})).
		status(t, http.StatusSeeOther).location(t, userPage+"/disable")
	if rec, ok := e.findAudit("admin.users.manage", audit.ResultDenied); !ok || rec.ErrorClass != "unconfirmed" {
		t.Fatalf("unconfirmed change not audited: %+v", rec)
	}
	result(c.submit(userPage+"/disable", userPage+"/disable", url.Values{"confirm": {"yes"}})).
		status(t, http.StatusSeeOther).location(t, userPage+"?done=disabled")
	if _, ok := e.findAudit("admin.user.disable", audit.ResultOK); !ok {
		t.Fatal("disable not audited")
	}
}

func TestResetAuthenticatorNeedsTheTypedName(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	action := userPage + "/reset-totp"
	result(c.get(action)).status(t, http.StatusOK).contains(t, "Reset authenticator for victor?", "Cannot be undone",
		"Type <code>victor</code> to confirm", `name="typed"`, "signed out everywhere")
	result(c.submit(action, action, url.Values{"confirm": {"yes"}, "typed": {"Victor"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "does not match", `aria-invalid="true"`)
	if rec, ok := e.findAudit("admin.users.manage", audit.ResultDenied); !ok || rec.ErrorClass != "confirm_mismatch" {
		t.Fatalf("mismatch not audited: %+v", rec)
	}
	if u, _ := e.db.Users().ByUsername(context.Background(), "victor"); !u.TOTPConfirmed {
		t.Fatal("reset happened without the typed name")
	}
	result(c.submit(action, action, url.Values{"confirm": {"yes"}, "typed": {"victor"}})).
		status(t, http.StatusOK).contains(t, "Authenticator reset")
}

func TestConfirmPageTakesTheStepUpCode(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	action := userPage + "/disable"
	e.clock.Advance(6 * time.Minute)
	result(c.get(action)).status(t, http.StatusOK).
		contains(t, "<strong>Disable account · victor</strong> needs a fresh code", `autocomplete="one-time-code"`)
	result(c.submit(action, action, url.Values{"confirm": {"yes"}, "code": {"000000"}})).
		status(t, http.StatusUnauthorized).contains(t, msgBadCode, "Disable account victor?")
	if u, _ := e.db.Users().ByUsername(context.Background(), "victor"); u.Disabled {
		t.Fatal("disabled with a wrong code")
	}
	result(c.submit(action, action, url.Values{"confirm": {"yes"}})).
		status(t, http.StatusUnauthorized).contains(t, "Enter the 6-digit code")
	old := c.jar[auth.SessionCookieName]
	result(c.submit(action, action, url.Values{"confirm": {"yes"}, "code": {e.code(e.secret)}})).
		status(t, http.StatusSeeOther).location(t, userPage+"?done=disabled")
	if c.jar[auth.SessionCookieName] == old {
		t.Fatal("session not rotated by the inline step-up")
	}
	if _, ok := e.findAudit("auth.stepup", audit.ResultOK); !ok {
		t.Fatal("inline step-up not audited")
	}
}

func TestSessionEndingGoesThroughConfirm(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	result(c.get(userPage+"/sessions/revoke-all")).status(t, http.StatusOK).contains(t, "End all sessions of victor?")
	result(c.submit(userPage+"/sessions/revoke-all", userPage+"/sessions/revoke-all", url.Values{"confirm": {"yes"}})).
		status(t, http.StatusSeeOther).location(t, userPage+"?done=revoked-all")
}

func TestRevokeTokenConfirmAndTypedWhenRecentlyUsed(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	rec := c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"dashboard"}, "expires": {"90"}})
	raw := tokenRE.FindStringSubmatch(rec.Body.String())[1]
	list := c.get("/settings/tokens").Body.String()
	id := regexp.MustCompile(`href="/settings/tokens/([0-9a-f]{32})/revoke"`).FindStringSubmatch(list)
	if id == nil || strings.Contains(list, `action="/settings/tokens/`+id[1]+`/revoke"`) {
		t.Fatal("tokens page must link to the confirm page, not post directly")
	}
	action := "/settings/tokens/" + id[1] + "/revoke"
	result(c.get(action)).status(t, http.StatusOK).contains(t, "Revoke token dashboard?", "Never used").lacks(t, `name="typed"`)
	if _, _, err := e.tokens.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	result(c.get(action)).contains(t, "Type <code>dashboard</code> to confirm", "used in the last 24 hours")
	result(c.submit(action, action, url.Values{"confirm": {"yes"}})).status(t, http.StatusUnprocessableEntity)
	result(c.submit(action, action, url.Values{"confirm": {"yes"}, "typed": {"dashboard"}})).
		status(t, http.StatusSeeOther).location(t, "/settings/tokens?done=token-revoked")
	result(c.get(action)).status(t, http.StatusNotFound)
}

func TestStepUpPageNamesTheAction(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/stepup?next=/settings/tokens")).status(t, http.StatusOK).
		contains(t, "already confirmed", `href="/settings/tokens"`, "Continue").lacks(t, `name="code"`)
	e.clock.Advance(6 * time.Minute)
	result(c.get("/stepup?next=/settings/tokens")).contains(t, "<strong>Manage API tokens</strong> needs a fresh code",
		`name="code"`, "change every 30 seconds")
	result(c.get("/stepup?next=/servers/r730xd/console")).contains(t, "<strong>Open the graphical console · Storage node R730XD</strong>")
	result(c.get("/stepup?next=/servers/r730xd/serial")).contains(t, "<strong>Open the serial console · Storage node R730XD</strong>")
	result(c.get("/stepup?next=/servers/nope/serial")).contains(t, "<strong>Make changes</strong>")
	result(c.get("/stepup?next=/servers/nope/console")).contains(t, "<strong>Make changes</strong>")
}

func TestRoleChangeUnchangedIsANoOp(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	userPage := victorPage(t, e, c)
	result(c.submit(userPage, userPage+"/role", url.Values{"role": {"viewer"}})).
		status(t, http.StatusSeeOther).location(t, userPage+"?done=role-unchanged")
	result(c.get(userPage+"?done=role-unchanged")).contains(t, "Role unchanged.")
	if _, ok := e.findAudit("admin.user.role", audit.ResultOK); ok {
		t.Fatal("an unchanged role must not write a change")
	}
}
