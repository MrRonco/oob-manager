package redfishmock

// WithExtraFixtures serves files from dir as well (checked before the main fixture
// directory): hand-written SYNTHETIC documents, such as the firmware member documents in
// testdata/redfish/synthetic-firmware, kept apart from the captured fixtures so the
// tests of the captured data stay as they are.
func WithExtraFixtures(dir string) Option {
	return func(c *config) { c.extra = append(c.extra, dir) }
}

// extraFixture reads name from the extra directories, first match wins.
func (s *Server) extraFixture(name string) ([]byte, bool) {
	for _, dir := range s.cfg.extra {
		if b, err := readFixture(dir, name); err == nil {
			return b, true
		}
	}
	return nil, false
}
