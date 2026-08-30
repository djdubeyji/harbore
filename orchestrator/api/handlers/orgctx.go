package handlers

import (
	"net/http"

	"github.com/google/uuid"
)

// activeOrgID reads the caller's active organization from the X-Org-Id header.
// The frontend sends it on every request; handlers verify membership before use.
func activeOrgID(r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.Header.Get("X-Org-Id"))
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}
