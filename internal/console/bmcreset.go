package console

// BMC restart (tech_doc §37): a BMC restart drops every console on the server, so the
// BMC reset service ends them first (audited stop rows with reason bmc_reset) and, once
// the BMC answers again, forgets what the app learned about the old BMC session (the
// VNC banner probe, the serial console's last attempt) so the cards say "Not checked
// yet" instead of a result from before the restart.

// reasonBMCReset: an admin restarted the server's BMC.
const reasonBMCReset endReason = "bmc_reset"

// EndForBMCReset ends the graphical console on serverID (if any) with reason bmc_reset
// and waits briefly for it to close. It reports whether one was running.
func (s *Service) EndForBMCReset(serverID string) bool {
	_, held := s.broker.active(serverID)
	s.broker.end(serverID, reasonBMCReset, shutdownWait)
	return held
}

// ForgetProbe drops the cached VNC banner probe of serverID; the probe loop runs it
// again on its next tick.
func (s *Service) ForgetProbe(serverID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.probes, serverID)
}

// EndForBMCReset ends the serial console on serverID (if any) with reason bmc_reset and
// waits briefly for it to close. It reports whether one was running.
func (s *SerialService) EndForBMCReset(serverID string) bool {
	_, held := s.broker.active(serverID)
	s.broker.end(serverID, reasonBMCReset, shutdownWait)
	return held
}

// ForgetAttempt drops the serial console's last connection attempt on serverID.
func (s *SerialService) ForgetAttempt(serverID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.last, serverID)
}
