package authz

import (
	"errors"
	"testing"
)

// expected is the full matrix from PRD §2 and tech_doc §6, written out by hand so a
// change to the implementation cannot silently change both sides at once.
// Columns: viewer, operator, admin.
var expected = map[Action][3]bool{
	ViewFleet:             {true, true, true},
	ViewServer:            {true, true, true},
	ViewLogs:              {true, true, true},
	ViewInventory:         {true, true, true},
	ViewFan:               {true, true, true},
	ViewOwnAudit:          {true, true, true},
	PowerOn:               {false, true, true},
	PowerGracefulStop:     {false, true, true},
	PowerGracefulRestart:  {false, true, true},
	PowerForceOff:         {false, false, true},
	PowerForceRestart:     {false, false, true},
	PowerCycle:            {false, false, true},
	FanLeaseCreate:        {false, true, true},
	FanLeaseEnd:           {false, true, true},
	ConsoleSerial:         {false, false, true},
	ConsoleSerialTakeover: {false, false, true},
	ConsoleVNC:            {false, false, true},
	ConsoleVNCTakeover:    {false, false, true},
	ConsoleKVMLaunch:      {false, false, true},
	AdminAudit:            {false, false, true},
	AdminAuditVerify:      {false, false, true},
	AdminAuditExport:      {false, false, true},
	AdminUsers:            {false, false, true},
	AdminTokens:           {false, false, true},
	AdminUsersManage:      {false, false, true},
	AdminTokensManage:     {false, false, true},
	AboutView:             {true, true, true},
	AdminGeneral:          {false, false, true},
	AdminGeneralManage:    {false, false, true},
	UserPrefs:             {true, true, true},
	AdminServers:          {false, false, true},
	AdminServersManage:    {false, false, true},
	// Notifications (tech_doc §26).
	AdminNotifications:       {false, false, true},
	AdminNotificationsManage: {false, false, true},
	// Integrations (tech_doc §34): the GELF target and the dashboard hints are admin-only
	// (viewers never learn the log server address); changing it needs a fresh step-up.
	AdminIntegrations:       {false, false, true},
	AdminIntegrationsManage: {false, false, true},
	// Maintenance mode, notes and acknowledgements (tech_doc §28).
	ServerMaintenance:   {false, true, true},
	ServerNotes:         {false, true, true},
	ServerNotesModerate: {false, false, true},
	EventAck:            {false, true, true},
	// BMC security checks (tech_doc §31): the summary is on the viewer's server page;
	// the findings (weaknesses of the BMC) need the operator role; re-running the checks
	// and accepting a risk are admin decisions. Accepting (and taking it back) silences a
	// finding, so it needs a fresh step-up like every other admin change; a re-run only
	// reads the BMC.
	SecurityView:   {false, true, true},
	SecurityRerun:  {false, false, true},
	SecurityAccept: {false, false, true},
	// BMC restart (tech_doc §37): monitoring goes blind and every console closes, the same
	// class as a forced power action, so admin with a fresh step-up.
	BMCReset: {false, false, true},
	// Firmware view (tech_doc §38): versions are read like the inventory (viewer, tokens
	// too); the CSV export is the same data; a re-scan is a BMC read on demand, operator,
	// sessions only, no step-up (it changes nothing).
	ViewFirmware:          {true, true, true},
	ExportFirmware:        {true, true, true},
	FirmwareRescan:        {false, true, true},
	FirmwareSkipUpdate:    {false, false, true},
	FirmwareCatalogCheck:  {false, true, true},
	FirmwareCatalogUpload: {false, false, true},
	// Sensor history (tech_doc §39): the pages' readings over time (viewer, tokens too);
	// exporting every sensor of a server at once is the largest export (operator, owner
	// decision 2026-10-23; sessions only, like every action above viewer).
	ViewHistory:      {true, true, true},
	ExportHistory:    {true, true, true},
	ExportHistoryAll: {false, true, true},
}

var expectedStepUp = map[Action]bool{
	PowerOn: true, PowerGracefulStop: true, PowerGracefulRestart: true,
	PowerForceOff: true, PowerForceRestart: true, PowerCycle: true,
	FanLeaseCreate: true, ConsoleSerial: true, ConsoleSerialTakeover: true, ConsoleVNC: true, ConsoleVNCTakeover: true, ConsoleKVMLaunch: true,
	AdminUsersManage: true, AdminTokensManage: true, AdminGeneralManage: true, AdminServersManage: true,
	AdminNotificationsManage: true, SecurityAccept: true, AdminIntegrationsManage: true, FirmwareSkipUpdate: true, FirmwareCatalogUpload: true,
	BMCReset: true,
}

var roles = [3]Role{RoleViewer, RoleOperator, RoleAdmin}

func TestMatrixCoversEveryAction(t *testing.T) {
	all := Actions()
	if len(all) != len(expected) {
		t.Fatalf("Actions() has %d entries, test matrix has %d", len(all), len(expected))
	}
	for _, a := range all {
		if _, ok := expected[a]; !ok {
			t.Errorf("action %q missing from test matrix", a)
		}
	}
}

func TestEveryRoleTimesActionForSessions(t *testing.T) {
	for action, want := range expected {
		for i, role := range roles {
			p := Principal{Kind: KindSession, Role: role}
			if got := Allowed(p, action); got != want[i] {
				t.Errorf("Allowed(%s, %s) = %v, want %v", role, action, got, want[i])
			}
		}
	}
}

func TestTokensAreReadOnlyRegardlessOfRole(t *testing.T) {
	for action, want := range expected {
		for _, role := range roles {
			p := Principal{Kind: KindToken, Role: role}
			wantTok := want[0] && action != ViewOwnAudit && action != AboutView && action != UserPrefs
			if got := Allowed(p, action); got != wantTok {
				t.Errorf("token Allowed(%s, %s) = %v, want %v", role, action, got, wantTok)
			}
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
		a    Action
	}{
		{"unknown action", Principal{Kind: KindSession, Role: RoleAdmin}, Action("server.delete")},
		{"empty action", Principal{Kind: KindSession, Role: RoleAdmin}, Action("")},
		{"unknown role", Principal{Kind: KindSession, Role: Role("root")}, ViewFleet},
		{"empty role", Principal{Kind: KindSession}, ViewFleet},
		{"unknown kind", Principal{Kind: Kind(""), Role: RoleAdmin}, ViewFleet},
		{"zero principal", Principal{}, ViewFleet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if Allowed(tc.p, tc.a) {
				t.Fatalf("Allowed(%+v, %q) = true, want false", tc.p, tc.a)
			}
		})
	}
}

func TestRequiresStepUp(t *testing.T) {
	for _, a := range Actions() {
		if got := RequiresStepUp(a); got != expectedStepUp[a] {
			t.Errorf("RequiresStepUp(%s) = %v, want %v", a, got, expectedStepUp[a])
		}
	}
	if !RequiresStepUp(Action("unknown")) {
		t.Error("unknown actions must require step-up (fail closed)")
	}
}

func TestAuthorize(t *testing.T) {
	op := Principal{Kind: KindSession, Role: RoleOperator}
	cases := []struct {
		name  string
		p     Principal
		a     Action
		fresh bool
		want  error
	}{
		{"read ok", op, ViewServer, false, nil},
		{"denied role", op, PowerForceOff, true, ErrForbidden},
		{"step-up missing", op, PowerOn, false, ErrStepUpRequired},
		{"step-up fresh", op, PowerOn, true, nil},
		{"end lease no step-up", op, FanLeaseEnd, false, nil},
		{"token write", Principal{Kind: KindToken, Role: RoleAdmin}, PowerOn, true, ErrForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Authorize(tc.p, tc.a, tc.fresh); !errors.Is(err, tc.want) {
				t.Fatalf("Authorize = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range roles {
		got, err := ParseRole(string(r))
		if err != nil || got != r {
			t.Errorf("ParseRole(%q) = %q, %v", r, got, err)
		}
	}
	for _, bad := range []string{"", "Admin", "root", " viewer"} {
		if _, err := ParseRole(bad); err == nil {
			t.Errorf("ParseRole(%q) accepted", bad)
		}
	}
}

func TestActionsReturnsCopy(t *testing.T) {
	a := Actions()
	a[0] = Action("tampered")
	if Actions()[0] == Action("tampered") {
		t.Fatal("Actions() exposes internal state")
	}
}

// TestSettingsS1Matrix is the settings-slice matrix (settings_design.md §5): every S1
// action × role × principal kind × step-up state, written out by hand.
func TestSettingsS1Matrix(t *testing.T) {
	type want struct{ viewer, operator, admin, adminStale error }
	cases := map[Action]want{
		AdminUsers:        {ErrForbidden, ErrForbidden, nil, nil},
		AdminTokens:       {ErrForbidden, ErrForbidden, nil, nil},
		AdminAudit:        {ErrForbidden, ErrForbidden, nil, nil},
		AdminAuditVerify:  {ErrForbidden, ErrForbidden, nil, nil},
		AdminUsersManage:  {ErrForbidden, ErrForbidden, nil, ErrStepUpRequired},
		AdminTokensManage: {ErrForbidden, ErrForbidden, nil, ErrStepUpRequired},
		AboutView:         {nil, nil, nil, nil},
		// Slice S2: General settings and each user's own display preferences.
		AdminGeneral:       {ErrForbidden, ErrForbidden, nil, nil},
		AdminGeneralManage: {ErrForbidden, ErrForbidden, nil, ErrStepUpRequired},
		UserPrefs:          {nil, nil, nil, nil},
		// Slice S3: Servers. Every change (incl. fingerprint fetch and test connection,
		// which contact a BMC) needs an admin with a fresh step-up.
		AdminServers:       {ErrForbidden, ErrForbidden, nil, nil},
		AdminServersManage: {ErrForbidden, ErrForbidden, nil, ErrStepUpRequired},
		// Slice S4: Integrations. Fetching a fingerprint and Send test also need the
		// manage action with a fresh step-up.
		AdminIntegrations:       {ErrForbidden, ErrForbidden, nil, nil},
		AdminIntegrationsManage: {ErrForbidden, ErrForbidden, nil, ErrStepUpRequired},
	}
	for a, w := range cases {
		for _, fresh := range []bool{true, false} {
			for i, role := range roles {
				exp := [3]error{w.viewer, w.operator, w.admin}[i]
				if role == RoleAdmin && !fresh {
					exp = w.adminStale
				}
				if errors.Is(exp, ErrStepUpRequired) && role != RoleAdmin {
					exp = ErrForbidden
				}
				got := Authorize(Principal{Kind: KindSession, Role: role}, a, fresh)
				if !errors.Is(got, exp) || (exp == nil && got != nil) {
					t.Errorf("session %s %s fresh=%v: %v, want %v", role, a, fresh, got, exp)
				}
				if err := Authorize(Principal{Kind: KindToken, Role: role}, a, fresh); !errors.Is(err, ErrForbidden) {
					t.Errorf("token %s %s fresh=%v: %v, want forbidden", role, a, fresh, err)
				}
			}
		}
	}
}

func TestFirmwareActions(t *testing.T) {
	tok := Principal{Kind: KindToken, Role: RoleAdmin}
	if !Allowed(tok, ViewFirmware) || !Allowed(tok, ExportFirmware) || Allowed(tok, FirmwareRescan) ||
		Allowed(tok, FirmwareSkipUpdate) || Allowed(tok, FirmwareCatalogCheck) || Allowed(tok, FirmwareCatalogUpload) {
		t.Fatal("tokens read and export the firmware view and never re-scan")
	}
	if RequiresStepUp(FirmwareRescan) || RequiresStepUp(ViewFirmware) || RequiresStepUp(ExportFirmware) {
		t.Fatal("the firmware view changes nothing: no step-up")
	}
}

func TestHistoryActions(t *testing.T) {
	for _, role := range roles {
		tok := Principal{Kind: KindToken, Role: role}
		if !Allowed(tok, ViewHistory) || !Allowed(tok, ExportHistory) || Allowed(tok, ExportHistoryAll) {
			t.Errorf("%s token: history view and export of one sensor, never every sensor at once", role)
		}
	}
	for _, a := range []Action{ViewHistory, ExportHistory, ExportHistoryAll} {
		if RequiresStepUp(a) {
			t.Errorf("%s reads: no step-up", a)
		}
	}
}
