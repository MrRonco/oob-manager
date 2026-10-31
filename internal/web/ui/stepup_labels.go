package ui

import "strings"

// keptActions names the server changes a kept form can replay after the step-up, by the
// route after /servers/{id}. "{nid}" stands for a note ID.
var keptActions = []struct{ route, label string }{
	{"/security/accept", "Accept a security risk"},
	{"/security/accept/remove", "Remove an accepted risk"},
	{"/maintenance", "Start maintenance"},
	{"/maintenance/end", "End maintenance"},
	{"/notes", "Add a note"},
	{"/notes/pin", "Pin a note"},
	{"/notes/{nid}", "Change a note"},
	{"/notes/{nid}/delete", "Delete a note"},
	{"/acks", "Acknowledge events"},
	{"/acks/remove", "Remove an acknowledgement"},
}

// keptFormLabel names the change a kept form posted to path will make ("" when path is
// not one of keptActions or names no configured server). name returns a configured
// server's name ("" for none); it is the only text interpolated.
func keptFormLabel(path string, name func(id string) string) string {
	id, rest, ok := strings.Cut(strings.TrimPrefix(path, "/servers/"), "/")
	if !ok || !strings.HasPrefix(path, "/servers/") || !serverIDPattern.MatchString(id) {
		return ""
	}
	for _, a := range keptActions {
		if routeMatches(a.route, "/"+rest) {
			if n := name(id); n != "" {
				return a.label + " · " + n
			}
			return ""
		}
	}
	return ""
}

// routeMatches compares a keptActions route with a path segment by segment.
func routeMatches(route, path string) bool {
	rs, ps := strings.Split(route, "/"), strings.Split(path, "/")
	if len(rs) != len(ps) {
		return false
	}
	for i, r := range rs {
		if r == "{nid}" {
			if _, ok := parseNoteID(ps[i]); !ok {
				return false
			}
			continue
		}
		if r != ps[i] {
			return false
		}
	}
	return true
}

// fleetName is the configured name of a fleet server ("" when unknown).
func (s *server) fleetName(id string) string {
	if v, ok := s.d.Fleet.Server(id); ok {
		return v.Name
	}
	return ""
}
