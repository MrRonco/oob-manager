package maint

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// DefaultEvery is how often Run looks for windows that start or expire.
const DefaultEvery = 15 * time.Second

// Recorder writes audit rows (*audit.Logger).
type Recorder = admin.Recorder

// Config wires a Service. DB and Audit are required for changes; without DB the service
// is empty and every change answers ErrUnavailable.
type Config struct {
	DB    *store.DB
	Audit Recorder
	// Emit sends the "maintenance started/ended" notifications (nil: none).
	Emit func(notify.Event)
	// ServerName names a server in notifications (nil or "": the id).
	ServerName func(id string) string
	Every      time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

// state is an immutable view of every window, note and acknowledgement.
type state struct {
	windows map[string]Window
	notes   map[string][]Note // per server: pinned first, then newest first
	acks    map[string]Ack    // by EventRef.key
	acksBy  map[string][]Ack  // per server, newest first
}

// Service manages maintenance windows, notes and acknowledgements.
type Service struct {
	cfg   Config
	st    atomic.Pointer[state]
	write sync.Mutex // serialises changes (reload after each)
}

// New loads the stored state.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Every <= 0 {
		cfg.Every = DefaultEvery
	}
	if cfg.DB != nil && cfg.Audit == nil {
		return nil, errors.New("maint: Audit is required with DB")
	}
	s := &Service{cfg: cfg}
	if err := s.reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) reload(ctx context.Context) error {
	st := &state{windows: map[string]Window{}, notes: map[string][]Note{}, acks: map[string]Ack{}, acksBy: map[string][]Ack{}}
	if s.cfg.DB != nil {
		if err := s.load(ctx, st); err != nil {
			return err
		}
	}
	s.st.Store(st)
	return nil
}

func (s *Service) load(ctx context.Context, st *state) error {
	repo := s.cfg.DB.Maint()
	ws, err := repo.Windows(ctx)
	if err != nil {
		return err
	}
	for _, w := range ws {
		st.windows[w.ServerID] = Window{ServerID: w.ServerID, StartsAt: w.StartsAt, EndsAt: w.EndsAt, Reason: w.Reason,
			By: w.CreatedBy, CreatedAt: w.CreatedAt, Notified: w.StartedNotified, RemindedAt: w.RemindedAt}
	}
	notes, err := repo.Notes(ctx)
	if err != nil {
		return err
	}
	for _, n := range notes {
		st.notes[n.ServerID] = append(st.notes[n.ServerID], Note{ID: n.ID, ServerID: n.ServerID, Body: n.Body,
			Pinned: n.Pinned, AuthorID: n.AuthorID, Author: n.Author, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt})
	}
	for id, list := range st.notes {
		slices.SortStableFunc(list, func(a, b Note) int { return boolRank(b.Pinned) - boolRank(a.Pinned) })
		st.notes[id] = list
	}
	acks, err := repo.Acks(ctx)
	if err != nil {
		return err
	}
	for _, a := range acks {
		ack := Ack{Ref: EventRef{ServerID: a.ServerID, Log: a.Log, EntryID: a.EntryID, Created: fromCreatedMS(a.CreatedMS)},
			Comment: a.Comment, By: a.AckedBy, At: a.AckedAt}
		st.acks[ack.Ref.key()] = ack
		st.acksBy[a.ServerID] = append(st.acksBy[a.ServerID], ack)
	}
	for id, list := range st.acksBy {
		slices.SortStableFunc(list, func(a, b Ack) int { return b.At.Compare(a.At) })
		st.acksBy[id] = list
	}
	return nil
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Available reports whether changes can be saved (a database is wired).
func (s *Service) Available() bool { return s.cfg.DB != nil }

// Window returns a server's window, active or scheduled (an expired one Run has not
// removed yet is not returned).
func (s *Service) Window(serverID string) (Window, bool) {
	w, ok := s.st.Load().windows[serverID]
	if !ok || w.ExpiredAt(s.cfg.Now()) {
		return Window{}, false
	}
	return w, true
}

// Active returns the server's window when it is active now.
func (s *Service) Active(serverID string) (Window, bool) {
	w, ok := s.Window(serverID)
	if !ok || !w.ActiveAt(s.cfg.Now()) {
		return Window{}, false
	}
	return w, true
}

// OpenEnded lists the active "until ended" windows that began at least OpenEndedAfter
// ago, oldest first (Overview's "Open-ended maintenance" warning).
func (s *Service) OpenEnded() []Window {
	now := s.cfg.Now()
	var out []Window
	for _, w := range s.st.Load().windows {
		if w.LongOpenEndedAt(now) {
			out = append(out, w)
		}
	}
	slices.SortFunc(out, func(a, b Window) int {
		return cmp.Or(a.StartsAt.Compare(b.StartsAt), cmp.Compare(a.ServerID, b.ServerID))
	})
	return out
}

// InMaintenance implements notify.Suppressor.
func (s *Service) InMaintenance(serverID string, now time.Time) bool {
	w, ok := s.st.Load().windows[serverID]
	return ok && w.ActiveAt(now)
}

// Notes lists a server's notes: the pinned one first, then newest first.
func (s *Service) Notes(serverID string) []Note { return slices.Clone(s.st.Load().notes[serverID]) }

// Note returns one note.
func (s *Service) Note(serverID string, id int64) (Note, bool) {
	for _, n := range s.st.Load().notes[serverID] {
		if n.ID == id {
			return n, true
		}
	}
	return Note{}, false
}

// AckOf returns the acknowledgement of an entry.
func (s *Service) AckOf(r EventRef) (Ack, bool) {
	a, ok := s.st.Load().acks[r.key()]
	return a, ok
}

// Acked implements notify.Suppressor.
func (s *Service) Acked(serverID, log, entryID string, created time.Time) bool {
	_, ok := s.AckOf(EventRef{ServerID: serverID, Log: log, EntryID: entryID, Created: created})
	return ok
}

// Acks lists a server's acknowledgements, newest first.
func (s *Service) Acks(serverID string) []Ack { return slices.Clone(s.st.Load().acksBy[serverID]) }

// change runs fn and its audit row in one transaction, then reloads.
func (s *Service) change(ctx context.Context, fn func(tx *store.Tx) error) error {
	if s.cfg.DB == nil {
		return ErrUnavailable
	}
	if err := s.cfg.DB.WithTx(ctx, fn); err != nil {
		return err
	}
	return s.reload(ctx)
}

func entry(a admin.Actor, serverID, action string, p map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		ServerID: serverID, Action: action, Params: p, Result: audit.ResultOK}
}

var systemActor = admin.Actor{Username: "system", Method: "system"}

func (s *Service) emit(e notify.Event) {
	if s.cfg.Emit != nil {
		s.cfg.Emit(e)
	}
}

func (s *Service) name(id string) string {
	if s.cfg.ServerName != nil {
		return cmp.Or(s.cfg.ServerName(id), id)
	}
	return id
}

// mapStoreErr turns store sentinels into the package's.
func mapStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, store.ErrInvalid):
		return errors.Join(ErrInvalid, err)
	default:
		return err
	}
}
