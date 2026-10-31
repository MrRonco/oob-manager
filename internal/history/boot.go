package history

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/store"
)

// The kernel's boot ID and uptime (re-check MEDIUM-N2): within one boot the uptime is
// real elapsed time that a wall clock step cannot fake, so a crash loop after a forward
// step cannot advance the retention clock 3 hours per restart. Pure file reads of
// /proc (no command is run); where /proc is not there (macOS, tests, other kernels) the
// janitor falls back to the in-process monotonic clock and, across a start, the 3-hour
// allowance.

// Linux /proc files read for the boot mark.
const (
	bootIDFile = "/proc/sys/kernel/random/boot_id"
	uptimeFile = "/proc/uptime"
)

// bootIDPattern is a boot ID as the kernel prints it (a UUID); uptimePattern its uptime
// in seconds, decimal only (no sign, exponent, hex, NaN or Inf).
var (
	bootIDPattern = regexp.MustCompile(`^[0-9a-f-]{1,64}$`)
	uptimePattern = regexp.MustCompile(`^[0-9]{1,10}(\.[0-9]{1,9})?$`)
)

// ReadBoot is the default Config.Boot: the boot ID and uptime from /proc, false when
// either is missing or malformed.
func ReadBoot() (store.BootMark, bool) {
	id, err := os.ReadFile(bootIDFile)
	if err != nil {
		return store.BootMark{}, false
	}
	up, err := os.ReadFile(uptimeFile)
	if err != nil {
		return store.BootMark{}, false
	}
	return parseBoot(string(id), string(up))
}

// parseBoot reads "<uuid>\n" and "<uptime seconds> <idle seconds>\n".
func parseBoot(id, uptime string) (store.BootMark, bool) {
	id = strings.TrimSpace(id)
	fields := strings.Fields(uptime)
	if !bootIDPattern.MatchString(id) || len(fields) == 0 || !uptimePattern.MatchString(fields[0]) {
		return store.BootMark{}, false
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return store.BootMark{}, false
	}
	return store.BootMark{ID: id, Uptime: time.Duration(secs * float64(time.Second))}, true
}
