package notify

import (
	"encoding/json"
	"fmt"
	"slices"

	"oob-manager/internal/store"
)

// options is the stored layout of a target's non-secret options (options_json).
type options struct {
	AllowPlaintext    bool     `json:"allow_plaintext"`
	IncludeDetail     bool     `json:"include_detail"`
	PushoverEmergency bool     `json:"pushover_emergency,omitempty"`
	EmailFrom         string   `json:"email_from,omitempty"`
	EmailTo           []string `json:"email_to,omitempty"`
	EmailSecurity     string   `json:"email_security,omitempty"`
}

// subscription is the stored layout of subs_json.
type subscription struct {
	Classes     []string `json:"classes"`
	MinSeverity string   `json:"min_severity"`
}

// toRow builds the row for t (secrets are sealed by the caller).
func toRow(t Target, enc []byte) (store.NotifyTargetRow, error) {
	opts, err := json.Marshal(options{AllowPlaintext: t.AllowPlaintext, IncludeDetail: t.IncludeDetail,
		PushoverEmergency: t.PushoverEmergency, EmailFrom: t.EmailFrom, EmailTo: t.EmailTo,
		EmailSecurity: string(t.EmailSecurity)})
	if err != nil {
		return store.NotifyTargetRow{}, fmt.Errorf("notify: encode options: %w", err)
	}
	classes := make([]string, 0, len(t.Classes))
	for _, c := range t.Classes {
		classes = append(classes, string(c))
	}
	subs, err := json.Marshal(subscription{Classes: classes, MinSeverity: t.MinSeverity.String()})
	if err != nil {
		return store.NotifyTargetRow{}, fmt.Errorf("notify: encode subscription: %w", err)
	}
	return store.NotifyTargetRow{ID: t.ID, Name: t.Name, Kind: string(t.Kind), URL: t.URL, Enabled: t.Enabled,
		OptionsJSON: string(opts), SubsJSON: string(subs), SecretVersion: t.SecretVersion, SecretEnc: enc,
		UpdatedAt: t.UpdatedAt, UpdatedBy: t.UpdatedBy}, nil
}

// fromRow decodes a stored target. A row that does not decode is an error (the caller
// skips and logs it: a bad row never stops the app).
func fromRow(r store.NotifyTargetRow) (Target, error) {
	var o options
	if err := json.Unmarshal([]byte(r.OptionsJSON), &o); err != nil {
		return Target{}, fmt.Errorf("notify: target %s: options do not decode", r.ID)
	}
	var s subscription
	if err := json.Unmarshal([]byte(r.SubsJSON), &s); err != nil {
		return Target{}, fmt.Errorf("notify: target %s: subscription does not decode", r.ID)
	}
	sev, err := ParseSeverity(s.MinSeverity)
	if err != nil {
		return Target{}, fmt.Errorf("notify: target %s: %w", r.ID, err)
	}
	t := Target{ID: r.ID, Name: r.Name, Kind: Kind(r.Kind), URL: r.URL, Enabled: r.Enabled,
		AllowPlaintext: o.AllowPlaintext, IncludeDetail: o.IncludeDetail, PushoverEmergency: o.PushoverEmergency,
		EmailFrom: o.EmailFrom, EmailTo: slices.Clone(o.EmailTo), EmailSecurity: EmailSecurity(o.EmailSecurity),
		MinSeverity: sev, Source: SourceDB, SecretVersion: r.SecretVersion, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
	for _, c := range s.Classes {
		cl, err := ParseClass(c)
		if err != nil {
			return Target{}, fmt.Errorf("notify: target %s: %w", r.ID, err)
		}
		t.Classes = append(t.Classes, cl)
	}
	return t, nil
}
