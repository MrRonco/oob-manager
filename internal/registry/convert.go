package registry

import (
	"slices"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

// serverOf builds the normalised config.Server of a database row. stored lists the
// credential slots the row has; their names become the server's credential refs.
func serverOf(r store.ServerRow, stored map[credstore.Slot]bool) config.Server {
	s := config.Server{
		ID: r.ID, Name: r.Name, Tags: slices.Clone(r.Tags),
		BMC:          config.BMCConfig{Address: r.Address, Kind: config.BMCKind(r.Kind), Port: r.Port},
		TLSPinSHA256: r.TLSPin, SSHHostKey: r.SSHHostKey,
		Fan: config.FanConfig{Mode: config.FanMode(r.FanMode), SafeMinPct: r.FanSafeMinPct, MaxLease: r.FanMaxLease},
		Console: config.ConsoleConfig{Serial: config.SerialKind(r.ConsoleSerial),
			Graphical: config.GraphicalKind(r.ConsoleGraphical),
			VNC:       config.VNCConfig{Port: r.VNCPort, PinSHA256: r.VNCPin},
			SSH:       config.SSHConfig{Port: r.SSHPort}},
		Power: config.PowerConfig{SelfHost: r.PowerSelfHost, Impact: slices.Clone(r.PowerImpact)},
	}
	if stored[credstore.SlotReadOnly] {
		s.Credentials.ReadOnly = string(credstore.SlotReadOnly)
	}
	if stored[credstore.SlotOperator] {
		s.Credentials.Operator = string(credstore.SlotOperator)
	}
	if stored[credstore.SlotVNC] {
		s.Credentials.VNC = string(credstore.SlotVNC)
	}
	return config.Normalise(s)
}

// rowOf is the database row of a (normalised) server; audit fields and Enabled are the
// caller's. File-only tuning (bmc.auth, bmc.timeouts, VNC TLS and quirks) is not stored:
// a database server always gets the kind defaults.
func rowOf(s config.Server) store.ServerRow {
	return store.ServerRow{ID: s.ID, Name: s.Name, Tags: slices.Clone(s.Tags), Kind: string(s.BMC.Kind),
		Address: s.BMC.Address, Port: s.BMC.Port, TLSPin: s.TLSPinSHA256, VNCPin: s.Console.VNC.PinSHA256,
		SSHHostKey: s.SSHHostKey, FanMode: string(s.Fan.Mode), FanSafeMinPct: s.Fan.SafeMinPct,
		FanMaxLease: s.Fan.MaxLease, ConsoleSerial: string(s.Console.Serial),
		ConsoleGraphical: string(s.Console.Graphical), VNCPort: s.Console.VNC.Port, SSHPort: s.Console.SSH.Port,
		PowerSelfHost: s.Power.SelfHost, PowerImpact: slices.Clone(s.Power.Impact)}
}

// withAllRefs fills every credential ref with its slot name: the server as it will be
// once its credentials are stored. Validation of a draft uses it, so only the missing
// credentials remain for the enable check.
func withAllRefs(s config.Server) config.Server {
	s.Credentials = config.CredentialRef{ReadOnly: string(credstore.SlotReadOnly),
		Operator: string(credstore.SlotOperator), VNC: string(credstore.SlotVNC)}
	return s
}
