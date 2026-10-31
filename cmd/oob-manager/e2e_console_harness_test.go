//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/bmc/redfishmock"
)

// mockOptions: the R240 (iDRAC9) offers the Dell GetKVMSession native console launch and
// the fan floor attributes; both simulate power control (ComputerSystem.Reset with short
// state transitions) and answer /wsman like a WS-Management service (the security checks'
// probe).
func mockOptions(id string) []redfishmock.Option {
	opts := []redfishmock.Option{redfishmock.WithPowerControl(e2ePowerTransition), redfishmock.WithWSMan(),
		redfishmock.WithManagerReset(e2eBMCDowntime(id))}
	if id == "r240" {
		opts = append(opts, redfishmock.WithKVMSession(), redfishmock.WithFanFloor(),
			redfishmock.WithOverlay(bigSELPath, bigSELEntries(bigSELCount))) // > 50 entries: the pager renders (R2-25)
	}
	return opts
}

// consoleYAML is each server's host key, credentials and console block: the R730XD has
// the VNC console (iDRAC8, so the black-screen quirks apply by default) over TLS pinned to
// the fake VNC server's certificate; both have an operator login and the bmcssh serial
// console pinned to their fake SSH server (the R730XD one speaks only the legacy iDRAC8
// algorithms, so the default idrac8_legacy_ssh quirk is exercised).
func (s *stack) consoleYAML(id string) string {
	key := `    ssh_host_key: "` + s.ssh[id].HostKeyLine() + `"
`
	if id != "r730xd" {
		return key + `    credentials: { readonly: ` + id + `-ro, operator: ` + id + `-op }
` + fanYAML(id) + `    console: { serial: bmcssh, graphical: none }
`
	}
	return key + fmt.Sprintf(`    credentials: { readonly: %[1]s-ro, operator: %[1]s-op, vnc: %[1]s-vnc }
%[3]s    console:
      serial: bmcssh
      graphical: vnc
      vnc: { port: 5901, tls: true, tls_pin_sha256: "%[2]s" }
`, id, s.vnc.PinSHA256(), fanYAML(id))
}

// startSSH starts the fake BMC SSH consoles: the R730XD echoes like a login prompt and
// needs the legacy iDRAC8 algorithms; the R240 host sends nothing (BIOS serial
// redirection off), which the page must handle. Both accept the operator login. In
// showcase mode the R730XD host has already printed a boot tail and a login prompt.
func startSSH(t *testing.T, showcase bool) map[string]*sshtest.Server {
	t.Helper()
	login := sshtest.Options{User: redfishmock.OperatorUser, Password: redfishmock.OperatorPassword}
	legacy, silent := login, login
	legacy.Legacy, silent.Silent = true, true
	if showcase {
		legacy.Transcript = showcaseTranscript
	}
	return map[string]*sshtest.Server{"r730xd": sshtest.New(t, legacy), "r240": sshtest.New(t, silent)}
}

// dialSSH sends each configured BMC SSH address (TEST-NET) to its fake; anything else is
// refused, so no real network is ever dialled.
func (s *stack) dialSSH(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == extraAddress+":22" && s.extraSSH != nil {
		return (&net.Dialer{}).DialContext(ctx, network, s.extraSSH.Addr())
	}
	for _, srv := range e2eServers() {
		if addr == srv.address+":22" {
			return (&net.Dialer{}).DialContext(ctx, network, s.ssh[srv.id].Addr())
		}
	}
	return nil, fmt.Errorf("e2e: unexpected SSH dial to %s", addr)
}

// dialVNC sends the R730XD's configured VNC address (TEST-NET) to the fake server;
// anything else is refused, so no real network is ever dialled.
func (s *stack) dialVNC(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != "192.0.2.10:5901" {
		return nil, fmt.Errorf("e2e: unexpected VNC dial to %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, s.vnc.Addr())
}

// serveVNCDebug exposes the fake VNC server's record on a loopback-only plain HTTP
// listener (dev harness only), so the Playwright smoke can check what reached the
// "BMC". It returns the base URL.
func serveVNCDebug(t *testing.T, s *stack) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /vnc", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": s.vnc.Keys(), "encodings": s.vnc.Encodings(),
			"updates": s.vnc.Stats().Updates, "auth_ok": s.vnc.Stats().AuthOK})
	})
	mux.HandleFunc("GET /ssh", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"input": string(s.ssh["r730xd"].Input()),
			"requests": s.ssh["r730xd"].RequestTypes(), "sessions": s.ssh["r730xd"].Sessions()})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}
