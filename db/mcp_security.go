package db

import (
	"encoding/json"
	"time"
)

// MCPPinQuarantinePrefix is the settings key prefix for quarantined MCP tools.
// Key layout: mcp_pin_quarantine:<server>:<tool> → JSON snapshot.
const MCPPinQuarantinePrefix = "mcp_pin_quarantine:"

// MCPPinEnforceKey is the settings key controlling whether a changed tool
// description blocks the tool (true, default) or only warns (false).
const MCPPinEnforceKey = "mcp_pin_enforce"

// MCPToolQuarantine is a snapshot of a tool whose description drifted from its
// approved baseline while enforcement was on. The tool is withheld from the
// model until an administrator approves the new description (which advances the
// baseline) or turns enforcement off.
type MCPToolQuarantine struct {
	ServerName string `json:"server_name"`
	ToolName   string `json:"tool_name"`
	OldHash    string `json:"old_hash"`
	NewHash    string `json:"new_hash"`
	Detail     string `json:"detail"`
	DetectedAt string `json:"detected_at"`
}

func pinQuarantineKey(server, tool string) string {
	return MCPPinQuarantinePrefix + server + ":" + tool
}

// SaveMCPToolQuarantine persists (or refreshes) a quarantine snapshot.
func (d *DB) SaveMCPToolQuarantine(q MCPToolQuarantine) error {
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	return d.SetSetting(pinQuarantineKey(q.ServerName, q.ToolName), string(b))
}

// GetMCPToolQuarantine returns the snapshot for one tool, if quarantined.
func (d *DB) GetMCPToolQuarantine(server, tool string) (*MCPToolQuarantine, error) {
	raw, ok, err := d.GetSetting(pinQuarantineKey(server, tool))
	if err != nil || !ok {
		return nil, err
	}
	var q MCPToolQuarantine
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return nil, err
	}
	return &q, nil
}

// ListMCPToolQuarantines returns every currently quarantined tool.
func (d *DB) ListMCPToolQuarantines() ([]MCPToolQuarantine, error) {
	all, err := d.ListSettingsByPrefix(MCPPinQuarantinePrefix)
	if err != nil {
		return nil, err
	}
	out := make([]MCPToolQuarantine, 0, len(all))
	for _, raw := range all {
		var q MCPToolQuarantine
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			continue // skip malformed snapshots rather than failing the whole list
		}
		out = append(out, q)
	}
	return out, nil
}

// ClearMCPToolQuarantine removes one tool's quarantine snapshot.
func (d *DB) ClearMCPToolQuarantine(server, tool string) error {
	return d.DeleteSetting(pinQuarantineKey(server, tool))
}

// ApproveMCPToolQuarantine approves a quarantined tool: it advances the pin
// baseline to the snapshot's new hash and clears the quarantine, so the next
// agent assembly trusts the new description and the tool reappears.
func (d *DB) ApproveMCPToolQuarantine(server, tool string) (*MCPToolQuarantine, error) {
	q, err := d.GetMCPToolQuarantine(server, tool)
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, nil // nothing to approve
	}
	baselineKey := "mcp_tool_desc_hash:" + server + ":" + tool
	if err := d.SetSetting(baselineKey, q.NewHash); err != nil {
		return nil, err
	}
	if err := d.ClearMCPToolQuarantine(server, tool); err != nil {
		return nil, err
	}
	return q, nil
}

// pinBaselineKey builds the settings key holding a tool's approved hash.
// Kept here so assembly and approval share one definition.
func pinBaselineKey(server, tool string) string {
	return "mcp_tool_desc_hash:" + server + ":" + tool
}

// GetMCPPinBaseline returns the approved description hash for a tool ("" if unset).
func (d *DB) GetMCPPinBaseline(server, tool string) (string, bool, error) {
	return d.GetSetting(pinBaselineKey(server, tool))
}

// SetMCPPinBaseline stores a tool's approved description hash.
func (d *DB) SetMCPPinBaseline(server, tool, hash string) error {
	return d.SetSetting(pinBaselineKey(server, tool), hash)
}

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
