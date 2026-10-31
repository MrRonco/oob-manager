package bmcsec

import "oob-manager/internal/firmware"

// CompareVersions compares firmware versions with the one comparison the app uses
// everywhere (firmware.CompareVersions, docs/tech_doc.md §38), so the fw.bmc check and the
// firmware view judge a BMC against security.min_firmware alike: dotted segments compare
// as numbers ("2.86.86.86" < "7.00.00.182", "7.10" = "7.10.0"); ok is false when the
// versions cannot be ordered (a number against letters, an empty segment): no ordering is
// guessed from text.
func CompareVersions(a, b string) (cmp int, ok bool) { return firmware.CompareVersions(a, b) }
