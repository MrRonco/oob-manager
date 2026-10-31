package main

import (
	"errors"
	"strings"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
)

// credLookup resolves a credential ref. secrets.Credentials (the age file) is one; a
// credSet adds the browser-managed servers' credentials.
type credLookup interface {
	Lookup(ref string) (secrets.Credential, error)
}

// dbRefPrefix starts the in-memory refs of browser-managed credentials. Age-file refs
// match ^[a-z0-9][a-z0-9_-]*$, so these never collide with one.
const dbRefPrefix = "db/"

var errNoCredential = errors.New("credential not available")

// dbRef is the in-memory ref of server id's credential in slot.
func dbRef(id string, slot credstore.Slot) string { return dbRefPrefix + id + "/" + string(slot) }

// credSet is the age file plus the opened database credentials, keyed by dbRef.
type credSet struct {
	file secrets.Credentials
	db   map[string]secrets.Credential
}

// Lookup implements credLookup.
func (c credSet) Lookup(ref string) (secrets.Credential, error) {
	if strings.HasPrefix(ref, dbRefPrefix) {
		cred, ok := c.db[ref]
		if !ok {
			return secrets.Credential{}, errNoCredential
		}
		return cred, nil
	}
	return c.file.Lookup(ref)
}

// withDBRefs returns s with each stored slot's ref replaced by its dbRef (a database
// server's refs are slot names).
func withDBRefs(s config.Server) config.Server {
	ref := func(v string, slot credstore.Slot) string {
		if v == "" {
			return ""
		}
		return dbRef(s.ID, slot)
	}
	s.Credentials = config.CredentialRef{ReadOnly: ref(s.Credentials.ReadOnly, credstore.SlotReadOnly),
		Operator: ref(s.Credentials.Operator, credstore.SlotOperator), VNC: ref(s.Credentials.VNC, credstore.SlotVNC)}
	return s
}
