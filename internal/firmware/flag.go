package firmware

// Flag is a closed enum of what the firmware view says about a component.
type Flag string

// Flags, worst first.
const (
	FlagBelowMinimum    Flag = "below_minimum"    // running < the minimum known good (warn)
	FlagUpdateUrgent    Flag = "update_urgent"    // the vendor lists a newer release rated Urgent (warn)
	FlagNotApplied      Flag = "not_applied"      // Dell: the BMC holds a newer image that was never installed (info)
	FlagUpdateAvailable Flag = "update_available" // the vendor lists a newer release (info)
	FlagCannotCompare   Flag = "cannot_compare"   // a minimum applies but the versions cannot be ordered (info)
	FlagStale           Flag = "stale_release"    // released longer ago than firmware.stale_after (info, off by default)
	FlagOK              Flag = "ok"               // a minimum applies and is met (quiet)
	FlagNone            Flag = ""                 // nothing applies (not shown)
)

func (f Flag) rank() int {
	switch f {
	case FlagBelowMinimum:
		return 0
	case FlagUpdateUrgent:
		return 1
	case FlagNotApplied:
		return 2
	case FlagUpdateAvailable:
		return 3
	case FlagCannotCompare:
		return 4
	case FlagStale:
		return 5
	case FlagOK:
		return 6
	case FlagNone:
		return 7
	default:
		return 8
	}
}

// Label is the flag as shown in the UI.
func (f Flag) Label() string {
	switch f {
	case FlagBelowMinimum:
		return "Below minimum"
	case FlagUpdateUrgent:
		return "Urgent update"
	case FlagNotApplied:
		return "Not applied"
	case FlagUpdateAvailable:
		return "Update available"
	case FlagCannotCompare:
		return "Cannot compare"
	case FlagStale:
		return "Stale release"
	case FlagOK:
		return "OK"
	case FlagNone:
		return ""
	default:
		return string(f)
	}
}

// Warn reports the flags the sidebar counts (posture worth acting on): below minimum
// and an Urgent vendor update (decision 5 of plan 08: the badge counts Urgent updates only).
func (f Flag) Warn() bool { return f == FlagBelowMinimum || f == FlagUpdateUrgent }

// Flagged reports every flag the "flagged only" filter keeps.
func (f Flag) Flagged() bool { return f.rank() < FlagOK.rank() }
