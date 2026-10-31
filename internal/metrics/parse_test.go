package metrics

import (
	"strconv"
	"strings"
)

// parseSampleLine is a minimal strict parser for one sample line of the text format:
// name{label="escaped",...} value. It is the test's independent check of Write.
func parseSampleLine(line string) bool {
	name, rest, hasLabels := strings.Cut(line, "{")
	if !hasLabels {
		n, v, ok := strings.Cut(line, " ")
		return ok && validName(n) && validValue(v)
	}
	if !validName(name) {
		return false
	}
	for {
		lname, after, ok := strings.Cut(rest, `="`)
		if !ok || !validName(lname) {
			return false
		}
		end := closingQuote(after)
		if end < 0 {
			return false
		}
		rest = after[end+1:]
		switch {
		case strings.HasPrefix(rest, ","):
			rest = rest[1:]
		case strings.HasPrefix(rest, "} "):
			return validValue(rest[2:])
		default:
			return false
		}
	}
}

// closingQuote finds the unescaped closing quote; only \\, \" and \n escapes are valid
// and a raw line feed never appears.
func closingQuote(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) || !strings.ContainsRune(`\"n`, rune(s[i+1])) {
				return -1
			}
			i++
		case '"':
			return i
		case '\n':
			return -1
		}
	}
	return -1
}

func validValue(v string) bool {
	switch v {
	case "NaN", "+Inf", "-Inf":
		return true
	}
	_, err := strconv.ParseFloat(v, 64)
	return err == nil
}
