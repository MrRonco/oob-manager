package display

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Zone is one entry of the time zone picker.
type Zone struct {
	Name  string // IANA name, the stored value ("America/New_York")
	Label string // "New York", "Argentina / Buenos Aires"
}

// ZoneGroup is one <optgroup>: a region and its zones, sorted by name.
type ZoneGroup struct {
	Region string
	Zones  []Zone
}

// ZoneGroups returns the curated, searchable zone list: UTC first, then every canonical
// IANA zone grouped by region. A fresh value each call.
func ZoneGroups() []ZoneGroup {
	groups := []ZoneGroup{{Region: "UTC", Zones: []Zone{{Name: UTC, Label: "UTC (Coordinated Universal Time)"}}}}
	for _, name := range canonicalZones() {
		region, city, _ := strings.Cut(name, "/")
		if groups[len(groups)-1].Region != region {
			groups = append(groups, ZoneGroup{Region: region})
		}
		last := &groups[len(groups)-1]
		last.Zones = append(last.Zones, Zone{Name: name, Label: strings.NewReplacer("_", " ", "/", " / ").Replace(city)})
	}
	return groups
}

// KnownZone reports whether name is UTC or a canonical zone of the curated list.
func KnownZone(name string) bool {
	if name == UTC {
		return true
	}
	_, found := slices.BinarySearch(canonicalZones(), name)
	return found
}

// LoadZone validates name against the curated list and loads it. Links ("US/Eastern"),
// abbreviations ("EST"), "Local" and paths are refused even though time.LoadLocation
// would accept some of them: the stored value is always a canonical name.
func LoadZone(name string) (*time.Location, error) {
	if !KnownZone(name) {
		return nil, fmt.Errorf("%w: unknown time zone %q (use a canonical IANA name such as America/New_York)", ErrInvalid, name)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("%w: time zone %q: %v", ErrInvalid, name, err)
	}
	return loc, nil
}
