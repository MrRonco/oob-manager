package ui

import "testing"

// TestSideValueAlwaysNamesMaintenance (review L4): a server in maintenance says so on its
// sidebar line, whatever else is true of it.
func TestSideValueAlwaysNamesMaintenance(t *testing.T) {
	m := &maintBadge{}
	for _, c := range []struct {
		row  summaryRow
		want string
	}{
		{summaryRow{Maint: m, Fresh: freshness{Stale: true, Age: "9 min"}}, "Maintenance · Stale · 9 min"},
		{summaryRow{Maint: m, Fresh: freshness{Restarting: true}}, "Maintenance · BMC restarting"},
		{summaryRow{Maint: m, Fresh: freshness{NoData: true, Stale: true}}, "Maintenance · No data"},
		{summaryRow{Maint: m}, "Maintenance"},
		{summaryRow{HostDown: true}, "Powered off"},
		{summaryRow{Hottest: meterView{Value: "41", Unit: "°C"}}, "41 °C"},
	} {
		if got := sideValue(c.row); got != c.want {
			t.Errorf("sideValue(%+v) = %q, want %q", c.row.Fresh, got, c.want)
		}
	}
}
