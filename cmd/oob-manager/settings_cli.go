package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"oob-manager/internal/config"
	"oob-manager/internal/registry"
)

// settingsCmd dispatches `settings import|export`.
func settingsCmd(e env, args []string) error {
	if len(args) == 0 {
		return errors.New("settings: expected import or export")
	}
	switch args[0] {
	case "import":
		return settingsImportCmd(e, args[1:])
	case "export":
		return settingsExportCmd(e, args[1:])
	default:
		return fmt.Errorf("settings: unknown subcommand %q (want import or export)", args[0])
	}
}

// settingsImportCmd copies config.yaml servers into the database (settings_design.md
// §2 migration): their credentials are decrypted from the age file and re-sealed into
// the database. The shell is trusted; the copies stay shadowed until the servers are
// removed from config.yaml and the app restarts.
func settingsImportCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("settings import", e.errOut)
	list := fs.String("servers", "", "comma-separated ids of config.yaml servers to import (required)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("settings import", pos, 0); err != nil {
		return err
	}
	ids := splitIDs(*list)
	if len(ids) == 0 {
		return errors.New("settings import: -servers is required")
	}
	c, err := openMutatingCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	creds, err := loadCredentials(c.cfg)
	if err != nil {
		return err
	}
	reg, err := c.openRegistry(e.ctx)
	if err != nil {
		return err
	}
	res, err := reg.Import(e.ctx, cliActor, ids, creds)
	if err != nil {
		return fmt.Errorf("settings import: nothing imported: %w", err)
	}
	for _, r := range res {
		note := ""
		if len(r.Dropped) > 0 {
			note = " (file-only settings not imported, the kind defaults apply: " + strings.Join(r.Dropped, ", ") + ")"
		}
		_, _ = fmt.Fprintf(e.errOut, "Imported %s with its credentials%s.\n", r.ID, note)
	}
	_, _ = fmt.Fprintf(e.out, "Now remove these servers from config.yaml and restart: %s\n", strings.Join(ids, ", "))
	_, _ = fmt.Fprintln(e.out, "Until then config.yaml wins and the imported copies are shown as shadowed.")
	return nil
}

func splitIDs(s string) []string {
	var out []string
	for _, id := range strings.Split(s, ",") {
		if id = strings.TrimSpace(id); id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// settingsExportCmd writes the effective runtime-managed settings as config.yaml
// fragments, without any secret: General values in force and every running server
// (browser-managed servers name their credentials "<id>-<slot>", the age-file entries
// to create if the server moves into the file).
func settingsExportCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("settings export", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if err = wantPositional("settings export", pos, 0); err != nil {
		return err
	}
	c, err := openCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	reg, err := c.openRegistry(e.ctx)
	if err != nil {
		return err
	}
	out, err := exportYAML(c.effective(), registry.Export(reg.Current()))
	if err != nil {
		return err
	}
	_, _ = fmt.Fprint(e.out, out)
	return nil
}

// exportYAML renders the effective settings. Durations are Go duration strings, so the
// document reads back with the same keys config.yaml uses.
func exportYAML(cfg config.Config, servers []config.Server) (string, error) {
	g := cfg.General()
	ui := map[string]any{"time_zone": g.TimeZone, "theme": g.Theme, "clock_format": g.ClockFormat,
		"date_format": g.DateFormat, "temperature_unit": g.TempUnit, "density": g.Density}
	if g.InstanceName != "" {
		ui["instance_name"] = g.InstanceName
	}
	doc := map[string]any{
		"poll": map[string]any{"interval": g.PollInterval.String(), "stale_multiplier": g.StaleMultiplier},
		"auth": map[string]any{"session_idle": g.SessionIdle.String(), "session_max": g.SessionMax.String(),
			"stepup_window": g.StepUpWindow.String()},
		"ratelimit": map[string]any{"login_ip_per_min": g.LoginIPPerMin, "login_acct_per_hour": g.LoginAcctPerHour},
		"ui":        ui,
		"settings":  map[string]any{"locked": nonNilList(cfg.Settings.Locked), "bmc_networks": cfg.Settings.BMCNetworks},
	}
	list := make([]any, 0, len(servers))
	for _, s := range servers {
		list = append(list, serverDoc(s))
	}
	doc["servers"] = list
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return "# oob-manager settings export: effective settings, no secrets\n" + string(b), nil
}

func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func serverDoc(s config.Server) map[string]any {
	quirks := func(q []config.VNCQuirk) []string {
		out := []string{}
		for _, x := range q {
			out = append(out, string(x))
		}
		return out
	}
	sshQuirks := []string{}
	for _, x := range s.Console.SSH.Quirks {
		sshQuirks = append(sshQuirks, string(x))
	}
	creds := map[string]any{"readonly": s.Credentials.ReadOnly}
	if s.Credentials.Operator != "" {
		creds["operator"] = s.Credentials.Operator
	}
	if s.Credentials.VNC != "" {
		creds["vnc"] = s.Credentials.VNC
	}
	fan := map[string]any{"mode": string(s.Fan.Mode)}
	if s.Fan.Mode != config.FanNone {
		fan["safe_min_pct"], fan["max_lease"] = s.Fan.SafeMinPct, s.Fan.MaxLease.String()
	}
	vnc := map[string]any{"port": s.Console.VNC.Port, "tls": s.Console.VNC.TLSEnabled(), "quirks": quirks(s.Console.VNC.Quirks)}
	if s.Console.VNC.PinSHA256 != "" {
		vnc["tls_pin_sha256"] = s.Console.VNC.PinSHA256
	}
	doc := map[string]any{"id": s.ID, "name": s.Name, "tags": nonNilList(s.Tags),
		"bmc": map[string]any{"address": s.BMC.Address, "kind": string(s.BMC.Kind), "port": s.BMC.Port,
			"auth": string(s.BMC.Auth), "timeouts": map[string]any{"request": s.BMC.Timeouts.Request.String(),
				"cycle": s.BMC.Timeouts.Cycle.String()}},
		"credentials": creds, "fan": fan,
		"console": map[string]any{"serial": string(s.Console.Serial), "graphical": string(s.Console.Graphical),
			"vnc": vnc, "ssh": map[string]any{"port": s.Console.SSH.Port, "quirks": sshQuirks}},
		"power": map[string]any{"self_host": s.Power.SelfHost, "impact": nonNilList(s.Power.Impact)},
	}
	if s.TLSPinSHA256 != "" {
		doc["tls_pin_sha256"] = s.TLSPinSHA256
	}
	if s.SSHHostKey != "" {
		doc["ssh_host_key"] = s.SSHHostKey
	}
	return doc
}
