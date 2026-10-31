package dellredfish

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// LifecycleLog reads the Dell Lifecycle Controller log: LogServices/Lclog/Entries
// (iDRAC9, and listed by iDRAC8) with the iDRAC8 legacy Managers/<id>/Logs/Lclog as
// fallback. ErrUnsupported when no candidate answers.
func (d *Driver) LifecycleLog(ctx context.Context, since time.Time) (bmc.EventLog, error) {
	res, err := d.base.Resources(ctx)
	if err != nil {
		return bmc.EventLog{}, err
	}
	for _, uri := range lifecycleCandidates(res.Manager, res.LogServices()) {
		log, err := d.base.ReadLog(ctx, uri, since)
		if errors.Is(err, bmc.ErrNotFound) {
			continue
		}
		return log, err
	}
	return bmc.EventLog{}, fmt.Errorf("lifecycle log: %w", bmc.ErrUnsupported)
}

func lifecycleCandidates(manager string, logServices []string) []string {
	var out []string
	for _, ls := range logServices {
		if strings.HasSuffix(strings.ToLower(ls), "/lclog") {
			out = append(out, ls+"/Entries")
		}
	}
	if manager != "" {
		out = append(out, manager+"/Logs/Lclog")
	}
	return out
}
