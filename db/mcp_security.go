package db

import (
	"time"
)

// MCPSecurityEvent is one assembly-time supply-chain signal detected while
// wiring MCP tools into an agent. It is distinct from MCPAuditEntry (which
// records per-call token usage): these rows record pinning drift (a tool
// description changed since baseline → suspected Rug Pull / poisoning) and
// namespace collisions (two servers produced the same qualified tool name →
// potential cross-server shadowing).
type MCPSecurityEvent struct {
	ID         int64     `json:"id"`
	Kind       string    `json:"kind"` // pin | shadow
	ServerName string    `json:"server_name"`
	ToolName   string    `json:"tool_name"`
	Detail     string    `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
}

// mcpSecurityKeep is the retention bound: events beyond this many rows are
// trimmed on each insert so the table stays bounded (same pattern as audit).
const mcpSecurityKeep = 500

// InsertMCPSecurityEvent appends an event and trims rows beyond the retention
// bound. Best-effort by design: callers log if this fails, tool assembly never
// blocks on persistence.
func (d *DB) InsertMCPSecurityEvent(e MCPSecurityEvent) error {
	var id int64
	if err := d.QueryRow(`
INSERT INTO mcp_security_events(kind, server_name, tool_name, detail)
VALUES ($1,$2,$3,$4) RETURNING id`,
		e.Kind, e.ServerName, e.ToolName, e.Detail).Scan(&id); err != nil {
		return err
	}
	_, err := d.Exec(`DELETE FROM mcp_security_events WHERE id <= $1`, id-mcpSecurityKeep)
	return err
}

// ListMCPSecurityEvents returns the newest events, optionally filtered by kind
// (empty = all). limit is clamped to [1,500].
func (d *DB) ListMCPSecurityEvents(kind string, limit int) ([]MCPSecurityEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`
SELECT id, kind, server_name, tool_name, detail, created_at
FROM mcp_security_events WHERE ($1 = '' OR kind = $1)
ORDER BY id DESC LIMIT $2`, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MCPSecurityEvent{}
	for rows.Next() {
		var e MCPSecurityEvent
		if err := rows.Scan(&e.ID, &e.Kind, &e.ServerName, &e.ToolName, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
