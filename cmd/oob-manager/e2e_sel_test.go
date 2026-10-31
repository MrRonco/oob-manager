//go:build e2e

package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// Seed data for the pager (audit R2-25): the recorded fixtures hold fewer than 50 log
// entries, so the Events page never showed its two pagers in CI and axe never saw the
// duplicate landmark. The R240 mock serves a synthetic SEL of bigSELCount entries
// instead; they are informational and old, so Needs attention, the 24 h feed and the
// notifications are unaffected, and only /events?severity=all&range=all pages.
const (
	bigSELCount = 60
	bigSELPath  = "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries"
)

// bigSELEntries is a Redfish LogEntryCollection of n OK entries, newest first, in the
// shape the iDRAC9 fixture uses.
func bigSELEntries(n int) string {
	base := time.Date(2024, 12, 28, 3, 0, 0, 0, time.FixedZone("EST", -5*3600))
	members := make([]map[string]any, 0, n)
	for i := n; i >= 1; i-- {
		members = append(members, map[string]any{
			"@odata.id":   fmt.Sprintf("%s/%d", bigSELPath, i),
			"@odata.type": "#LogEntry.v1_14_0.LogEntry",
			"Created":     base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			"Description": fmt.Sprintf("Log Entry %d", i),
			"EntryCode":   "Assert",
			"EntryType":   "SEL",
			"Id":          fmt.Sprint(i),
			"Message":     fmt.Sprintf("Synthetic informational event %d of %d (e2e seed).", i, n),
			"MessageId":   "SYN0001",
			"Name":        fmt.Sprintf("Log Entry %d", i),
			"SensorType":  "System Event",
			"Severity":    "OK",
		})
	}
	doc := map[string]any{
		"@odata.context":      "/redfish/v1/$metadata#LogEntryCollection.LogEntryCollection",
		"@odata.id":           bigSELPath,
		"@odata.type":         "#LogEntryCollection.LogEntryCollection",
		"Description":         "System Event Logs for this manager",
		"Members":             members,
		"Members@odata.count": n,
		"Name":                "Log Entry Collection",
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err) // a fixed document; cannot fail
	}
	return string(b)
}
