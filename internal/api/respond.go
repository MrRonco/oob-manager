package api

import (
	"encoding/json"
	"net/http"
	"time"

	"oob-manager/internal/bmc"
)

// writeJSON writes v with status 200. Encoding errors after the header is sent can
// only be a broken connection.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// list is the {data, meta} envelope for collections.
type list[T any] struct {
	Data []T `json:"data"`
	Meta any `json:"meta"`
}

// timePtr renders a zero time as JSON null.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// reading renders an absent reading as JSON null.
func reading(r bmc.Reading) *float64 {
	if !r.Valid {
		return nil
	}
	v := r.Value
	return &v
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
