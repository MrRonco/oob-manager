package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/store"
)

// LinkInfo is what the enrolment page may show before the link is redeemed.
type LinkInfo struct {
	Username  string
	Purpose   store.EnrolPurpose
	ExpiresAt time.Time
}

// LookupLink checks a link without using it. Unknown, malformed, used and expired links
// and links of disabled accounts are all ErrLinkInvalid.
func (s *Service) LookupLink(ctx context.Context, raw string) (LinkInfo, error) {
	tok, u, err := s.findLink(ctx, raw)
	if err != nil {
		return LinkInfo{}, err
	}
	return LinkInfo{Username: u.Username, Purpose: tok.Purpose, ExpiresAt: tok.ExpiresAt}, nil
}

func (s *Service) findLink(ctx context.Context, raw string) (store.EnrolmentToken, store.User, error) {
	hash, ok := auth.HashLinkToken(raw)
	if !ok {
		return store.EnrolmentToken{}, store.User{}, ErrLinkInvalid
	}
	tok, err := s.cfg.DB.Enrolments().ByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return store.EnrolmentToken{}, store.User{}, ErrLinkInvalid
	}
	if err != nil {
		return store.EnrolmentToken{}, store.User{}, err
	}
	if !tok.UsedAt.IsZero() || !s.cfg.Now().Before(tok.ExpiresAt) {
		return store.EnrolmentToken{}, store.User{}, ErrLinkInvalid
	}
	u, err := s.cfg.DB.Users().ByID(ctx, tok.UserID)
	if err != nil || u.Disabled {
		return store.EnrolmentToken{}, store.User{}, ErrLinkInvalid
	}
	return tok, u, nil
}

// RedeemLink uses a link once: it sets the user's password, replaces the authenticator
// with a fresh unconfirmed secret and ends any session. The returned enrollment is a
// secret to show once; the user then confirms a code (auth.ConfirmTOTP) to finish.
func (s *Service) RedeemLink(ctx context.Context, raw, password, ip string) (auth.TOTPEnrollment, string, error) {
	tok, u, err := s.findLink(ctx, raw)
	if err != nil {
		return auth.TOTPEnrollment{}, "", err
	}
	if err = auth.ValidatePassword(password); err != nil {
		return auth.TOTPEnrollment{}, "", invalidInput(fmt.Sprintf("password must be %d-%d characters",
			auth.MinPasswordLen, auth.MaxPasswordLen))
	}
	pwHash, err := s.cfg.Hasher.Hash(ctx, password) // before the tx: argon2 is slow
	if err != nil {
		return auth.TOTPEnrollment{}, "", err
	}
	enr, err := auth.NewTOTPEnrollment(s.cfg.Issuer, u.Username)
	if err != nil {
		return auth.TOTPEnrollment{}, "", err
	}
	enc, err := s.cfg.Sealer.Seal([]byte(enr.Secret), []byte(u.ID))
	if err != nil {
		return auth.TOTPEnrollment{}, "", fmt.Errorf("admin: seal TOTP secret: %w", err)
	}
	e := audit.Entry{Principal: u.Username, AuthMethod: "link", Role: string(u.Role), SrcIP: ip,
		Action: "auth.enrol", Params: map[string]any{"purpose": string(tok.Purpose)}, Result: audit.ResultOK}
	err = s.change(ctx, func(tx *store.Tx) (audit.Entry, error) {
		return e, redeemIn(ctx, tx, tok.TokenHash, u.ID, pwHash, enc, s.cfg.Now())
	})
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, ErrLinkInvalid) {
		return auth.TOTPEnrollment{}, "", ErrLinkInvalid
	}
	if err != nil {
		return auth.TOTPEnrollment{}, "", err
	}
	return enr, u.Username, nil
}

// redeemIn claims the link (single-use, in SQL) and applies the new credentials.
func redeemIn(ctx context.Context, tx *store.Tx, hash []byte, userID, pwHash string, enc []byte, now time.Time) error {
	claimed, err := tx.Enrolments().Consume(ctx, hash, now)
	if err != nil {
		return err
	}
	u, err := tx.Users().ByID(ctx, userID)
	if err != nil || claimed.UserID != userID || u.Disabled {
		return ErrLinkInvalid
	}
	if err = tx.Users().SetPasswordHash(ctx, userID, pwHash); err != nil {
		return err
	}
	if err = tx.Users().SetTOTPSecret(ctx, userID, enc); err != nil {
		return err
	}
	_, err = tx.Sessions().DeleteForUser(ctx, userID)
	return err
}
