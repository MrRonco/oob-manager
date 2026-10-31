package settings

import (
	"fmt"
	"sync/atomic"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Source is where a key's effective value comes from.
type Source string

// Sources, in precedence order.
const (
	SourceFile    Source = "file"
	SourceDB      Source = "db"
	SourceDefault Source = "default"
)

// Field is one key of the effective settings: its value as the form shows it, where
// it comes from and who last saved it from the browser.
type Field struct {
	Spec
	Value string
	// Default is the value without a saved row (the built-in default, as the form shows it).
	Default   string
	Source    Source
	UpdatedAt time.Time
	UpdatedBy string
}

// FileManaged reports whether config.yaml sets the key (it wins; read-only in the UI).
func (f Field) FileManaged() bool { return f.Source == SourceFile }

// Effective is the resolved General and Integrations sections. It is a value: the Provider publishes a
// new one on every change and nobody modifies a published one.
type Effective struct {
	General config.General
	// Rev is the settings revision this was built from (forms carry it).
	Rev int64
	// Locked is true when settings.locked lists the General section.
	Locked bool
	fields []Field
	// Integrations is the GELF audit target in force (file > DB > default, tech_doc
	// §34); IntegrationsLocked is settings.locked listing integrations.
	Integrations       config.GELF
	IntegrationsLocked bool
	// IntegrationsNote explains saved GELF rows that are not in force because together
	// they no longer validate (for example after allowed_networks was narrowed); "" when
	// none. The page and Overview show it.
	IntegrationsNote string
	intFields        []Field
	// Ignored explains database rows that were not applied (shadowed by the file, or
	// invalid against the current bounds); for the startup log.
	Ignored []string
}

// Fields returns every General key in display order (a fresh slice).
func (e Effective) Fields() []Field { return append([]Field(nil), e.fields...) }

// Field returns one key.
func (e Effective) Field(key string) (Field, bool) {
	for _, f := range e.fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// Editable reports whether the browser may change key.
func (e Effective) Editable(key string) bool {
	f, ok := e.Field(key)
	return ok && !e.Locked && !f.FileManaged()
}

// Resolve applies file > DB > default. file must be a loaded (defaulted, validated)
// Config; rows are the saved settings_kv rows. A row for a key the file sets is
// ignored (shadowed); a row that fails to decode or, combined with the rest, fails
// config.ValidateGeneral is ignored too, so a bad row can never stop the app.
func Resolve(file config.Config, rows []store.SettingRow, rev int64) Effective {
	g := file.General()
	var ignored []string
	saved := map[string]store.SettingRow{}
	for _, row := range rows {
		spec, known := specFor(row.Key)
		switch {
		case !known:
			continue // an Integrations key (resolveIntegrations), or one this binary does not manage
		case file.FileSets(row.Key):
			ignored = append(ignored, row.Key+": shadowed by config.yaml")
			continue
		}
		v, err := spec.decode(row.ValueJSON)
		if err != nil {
			ignored = append(ignored, fmt.Sprintf("%s: unreadable value %s", row.Key, row.ValueJSON))
			continue
		}
		next := set(g, row.Key, v)
		if p := config.ValidateGeneral(next, file.Poll.MinInterval); len(p) > 0 {
			ignored = append(ignored, row.Key+": "+p[0])
			continue
		}
		g, saved[row.Key] = next, row
	}
	gelf, gsaved, gignored, gnote := resolveIntegrations(file, rows)
	return Effective{General: g, Rev: rev, Locked: file.Locked(config.SectionGeneral),
		fields: fieldsOf(file, g, saved), Ignored: append(ignored, gignored...),
		Integrations: gelf, IntegrationsLocked: file.Locked(config.SectionIntegrations), IntegrationsNote: gnote,
		intFields: integrationFieldsOf(file, gelf, gsaved)}
}

func fieldsOf(file config.Config, g config.General, saved map[string]store.SettingRow) []Field {
	specs := GeneralSpecs()
	out := make([]Field, 0, len(specs))
	for _, s := range specs {
		f := Field{Spec: s, Value: s.display(get(g, s.Key)), Default: s.display(get(file.General(), s.Key)),
			Source: SourceDefault}
		if row, ok := saved[s.Key]; ok {
			f.Source, f.UpdatedAt, f.UpdatedBy = SourceDB, row.UpdatedAt, row.UpdatedBy
		}
		if file.FileSets(s.Key) {
			f.Source = SourceFile
		}
		out = append(out, f)
	}
	return out
}

// Provider holds the current Effective settings for lock-free reads. Readers call
// Current per use, so a change applies to the next request without a restart (except
// the keys whose Spec says Restart).
type Provider struct {
	cur     atomic.Pointer[Effective]
	started config.General
	changed chan struct{}
}

// NewProvider publishes e; its General is also recorded as what the running process
// started with (for the restart-only keys).
func NewProvider(e Effective) *Provider {
	p := &Provider{started: e.General, changed: make(chan struct{}, 1)}
	p.cur.Store(&e)
	return p
}

// Current returns the published settings.
func (p *Provider) Current() Effective { return *p.cur.Load() }

// Started returns the General values the process started with.
func (p *Provider) Started() config.General { return p.started }

// PendingRestart lists the restart-only keys whose saved value differs from the
// running one.
func (p *Provider) PendingRestart() []string {
	cur := p.Current().General
	var out []string
	for _, s := range GeneralSpecs() {
		if s.Restart && get(cur, s.Key) != get(p.started, s.Key) {
			out = append(out, s.Key)
		}
	}
	return out
}

func (p *Provider) publish(e Effective) {
	p.cur.Store(&e)
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

// Changes signals (coalesced) that Current changed, for consumers that rebuild state
// from it (the pollers: poll.interval applies through fleet.Apply).
func (p *Provider) Changes() <-chan struct{} { return p.changed }

// IntegrationFields returns every Integrations key in display order (a fresh slice).
func (e Effective) IntegrationFields() []Field { return append([]Field(nil), e.intFields...) }

// IntegrationField returns one Integrations key.
func (e Effective) IntegrationField(key string) (Field, bool) {
	for _, f := range e.intFields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// IntegrationEditable reports whether the browser may change an Integrations key.
func (e Effective) IntegrationEditable(key string) bool {
	f, ok := e.IntegrationField(key)
	return ok && !e.IntegrationsLocked && !f.FileManaged()
}
