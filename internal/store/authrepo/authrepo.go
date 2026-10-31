// Package authrepo adapts the SQLite repositories of package store to the repository
// interfaces package auth declares (auth.UserRepo, SessionRepo, LockoutRepo, TokenRepo).
//
// It exists so that neither package imports the other: store stays a plain persistence
// layer and auth stays testable with in-memory fakes. The adapters only translate types
// and error sentinels; every atomicity guarantee auth relies on is implemented by a
// single SQL statement or transaction inside store (see the store method comments).
package authrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// Repos bundles the four adapters.
type Repos struct {
	Users    auth.UserRepo
	Sessions auth.SessionRepo
	Lockouts auth.LockoutRepo
	Tokens   auth.TokenRepo
}

// New returns adapters backed by db.
func New(db *store.DB) Repos {
	return Repos{
		Users:    Users(db.Users()),
		Sessions: Sessions(db.Sessions()),
		Lockouts: Lockouts(db.Lockouts()),
		Tokens:   Tokens(db.Tokens()),
	}
}

// mapErr turns store sentinels into the auth sentinels auth's interfaces promise.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w (%w)", auth.ErrNotFound, err)
	default:
		return err
	}
}

// Users adapts a store.UserRepository.
func Users(r store.UserRepository) auth.UserRepo { return userRepo{r} }

type userRepo struct{ r store.UserRepository }

func (u userRepo) CreateFirst(ctx context.Context, x auth.User) error {
	err := u.r.CreateFirst(ctx, toStoreUser(x))
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("%w (%w)", auth.ErrUsersExist, err)
	}
	return err
}

func (u userRepo) GetByUsername(ctx context.Context, username string) (auth.User, error) {
	x, err := u.r.ByUsername(ctx, username)
	if err != nil {
		return auth.User{}, mapErr(err)
	}
	return fromStoreUser(x), nil
}

func (u userRepo) GetByID(ctx context.Context, id string) (auth.User, error) {
	x, err := u.r.ByID(ctx, id)
	if err != nil {
		return auth.User{}, mapErr(err)
	}
	return fromStoreUser(x), nil
}

func (u userRepo) SetPasswordHash(ctx context.Context, id, hash string) error {
	return mapErr(u.r.SetPasswordHash(ctx, id, hash))
}

func (u userRepo) SetTOTP(ctx context.Context, id string, secretEnc []byte, confirmed bool) error {
	return mapErr(u.r.SetTOTP(ctx, id, secretEnc, confirmed))
}

func (u userRepo) ReEnrollTOTP(ctx context.Context, id string, secretEnc []byte) error {
	return mapErr(u.r.SetTOTPSecret(ctx, id, secretEnc))
}

func (u userRepo) AdvanceTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	ok, err := u.r.AdvanceTOTPStep(ctx, id, step)
	return ok, mapErr(err)
}

func toStoreUser(u auth.User) store.User {
	return store.User{
		ID: u.ID, Username: u.Username, Role: store.Role(u.Role), PwHash: u.PasswordHash,
		TOTPSecretEnc: clone(u.TOTPSecretEnc), TOTPConfirmed: u.TOTPConfirmed,
		TOTPLastStep: u.TOTPLastStep, Disabled: u.Disabled, CreatedAt: u.CreatedAt,
	}
}

func fromStoreUser(u store.User) auth.User {
	return auth.User{
		ID: u.ID, Username: u.Username, Role: authz.Role(u.Role), PasswordHash: u.PwHash,
		TOTPSecretEnc: clone(u.TOTPSecretEnc), TOTPConfirmed: u.TOTPConfirmed,
		TOTPLastStep: u.TOTPLastStep, Disabled: u.Disabled, CreatedAt: u.CreatedAt,
	}
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// Lockouts adapts a store.LockoutRepository.
func Lockouts(r store.LockoutRepository) auth.LockoutRepo { return lockoutRepo{r} }

type lockoutRepo struct{ r store.LockoutRepository }

func (l lockoutRepo) Get(ctx context.Context, key string) (auth.LockoutState, error) {
	st, err := l.r.Get(ctx, key)
	return auth.LockoutState{Failures: st.Failures, LastFailure: st.LastFailure}, err
}

func (l lockoutRepo) RecordFailure(ctx context.Context, key string, at time.Time) (auth.LockoutState, error) {
	st, err := l.r.RecordFailure(ctx, key, at)
	return auth.LockoutState{Failures: st.Failures, LastFailure: st.LastFailure}, err
}

func (l lockoutRepo) Reset(ctx context.Context, key string) error { return l.r.Reset(ctx, key) }
