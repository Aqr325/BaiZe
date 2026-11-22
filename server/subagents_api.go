package server

import (
	"database/sql"
	"net/http"
)

// listSubagents returns the durable subagent ledger, optionally filtered by a
// parent session (?parent=). Backed by subagent_runs; the in-memory lifecycle
// registry remains the authority for live state, but the ledger is the source
// for the UI list after a restart.
func (s *Server) listSubagents(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	parent := r.URL.Query().Get("parent")
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)
	items, err := s.m.pg.ListSubagents(parent, limit)
	if err != nil {
		writeErr(w, 500, "failed to list subagents: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// cancelSubagent requests an in-flight subagent be interrupted. It addresses
// the child by its ledger subagent id (the caller cannot know the capability
// HMAC) and reports the CancelResult directly.
func (s *Server) cancelSubagent(w http.ResponseWriter, r *http.Request) {
	if s.delegationSvc == nil {
		writeErr(w, 503, "multi-agent delegation is not wired")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "missing subagent id")
		return
	}
	cr := s.delegationSvc.CancelByID(id, r.URL.Query().Get("reason"))
	writeJSON(w, 200, cr)
}

// getSubagent returns one ledger row by id.
func (s *Server) getSubagent(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	item, err := s.m.pg.GetSubagent(id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, 404, "subagent not found")
			return
		}
		writeErr(w, 500, "failed to get subagent: "+err.Error())
		return
	}
	writeJSON(w, 200, item)
}
