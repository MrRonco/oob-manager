package config

import (
	"strings"
	"unicode"
)

// maxInstanceName bounds ui.instance_name (it is shown in the header bar).
const maxInstanceName = 64

// validInstanceName checks ui.instance_name (a General key since v0.9.1), from the file
// or the browser alike: plain printable text without markup characters or surrounding
// spaces, at most maxInstanceName bytes.
func validInstanceName(p problems, name string) problems {
	switch {
	case len(name) > maxInstanceName:
		return p.add("ui.instance_name must be at most %d bytes", maxInstanceName)
	case strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) || strings.ContainsRune("<>&\"'", r) }):
		return p.add("ui.instance_name must be plain printable text (no control characters or < > & \" ')")
	case strings.TrimSpace(name) != name:
		return p.add("ui.instance_name must not start or end with spaces")
	}
	return p
}
