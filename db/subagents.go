package db

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Autumn-27/baize/agent/delegation"
)

// SubagentRun is one durable ledger row in subagent_runs. It mirrors the
// subagent_lifecycle record hermes keeps across restarts, persisted to
// PostgreSQL instead of a per-process SQLite file.
type SubagentRun struct {
	ID                   int64          `json:"id"`
	SubagentID           string         `json:"subagent_id"`
	ParentSessionID      string         `json:"parent_session_id"`
	ParentTaskID         int64          `json:"parent_task_id"`
	CorrelationID        string         `json:"correlation_id"`
	Goal                 string         `json:"goal"`
	Context              string         `json:"context"`
	Role                 string         `json:"role"`
	Model                string         `json:"model"`
	Provider             string         `json:"provider"`
	AllowedToolsets      []string       `json:"allowed_toolsets"`
	Metadata             map[string]any `json:"metadata"`
	State                string         `json:"state"`
	Depth                int            `json:"depth"`
	StartedAt            *time.Time     `json:"started_at,omitempty"`
	CompletedAt          *time.Time     `json:"completed_at,omitempty"`
	Summary              string         `json:"summary"`
	StructuredPayload    map[string]any `json:"structured_payload,omitempty"`
	ErrorClassification  string         `json:"error_classification"`
	ErrorMessage         string         `json:"error_message"`
	UsageMetadata        map[string]any `json:"usage_metadata,omitempty"`
	ToolExecutionSummary map[string]any `json:"tool_execution_summary,omitempty"`
	ResultHash           string         `json:"result_hash"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

// ---- Persistence interface (agent/delegation.Persistence) ----

// UpsertLaunch records a new subagent before its child starts running.
func (d *DB) UpsertLaunch(h delegation.Handle, req *delegation.LaunchRequest) error {
	meta, err := json.Marshal(mapOrEmpty(req.Metadata))
	if err != nil {
		meta = []byte("{}")
	}
	tools, err := json.Marshal(req.AllowedToolsets)
	if err != nil {
		tools = []byte("[]")
	}
	created := time.Unix(int64(h.CreatedAt), 0)
	_, err = d.Exec(`
INSERT INTO subagent_runs
  (subagent_id, parent_session_id, parent_task_id, correlation_id,
   goal, context, role, model, provider, allowed_toolsets, metadata,
   state, depth, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
ON CONFLICT (subagent_id) DO UPDATE SET
   parent_session_id = EXCLUDED.parent_session_id,
   parent_task_id    = EXCLUDED.parent_task_id,
   correlation_id    = EXCLUDED.correlation_id,
   goal              = EXCLUDED.goal,
   context           = EXCLUDED.context,
   role              = EXCLUDED.role,
   model             = EXCLUDED.model,
   provider          = EXCLUDED.provider,
   allowed_toolsets  = EXCLUDED.allowed_toolsets,
   metadata          = EXCLUDED.metadata,
   state             = EXCLUDED.state,
   depth             = EXCLUDED.depth,
   updated_at        = now()`,
		h.SubagentID, h.ParentSessionID, req.ParentTaskID, h.CorrelationID,
		req.Goal, req.Context, req.Role, req.Model, req.Provider,
		string(tools), string(meta), string(delegation.StatePending), h.Depth, created)
	return err
}

// UpdateState records a non-terminal state transition.
func (d *DB) UpdateState(subagentID string, st delegation.State, ts float64) error {
	at := time.Unix(int64(ts), 0)
	_, err := d.Exec(`
UPDATE subagent_runs
SET state = $1, updated_at = $2,
    started_at = COALESCE(started_at, CASE WHEN $1 IN ('RUNNING','STARTING') THEN $2::timestamptz ELSE NULL::timestamptz END)
WHERE subagent_id = $3`,
		string(st), at, subagentID)
	return err
}

// UpdateResult records the child's terminal result.
func (d *DB) UpdateResult(subagentID string, r delegation.Result) error {
	structured, err := json.Marshal(mapOrEmpty(r.StructuredPayload))
	if err != nil {
		structured = []byte("{}")
	}
	usage, err := json.Marshal(mapOrEmpty(r.UsageMetadata))
	if err != nil {
		usage = []byte("{}")
	}
	tools, err := json.Marshal(mapOrEmpty(r.ToolExecutionSummary))
	if err != nil {
		tools = []byte("{}")
	}
	completed := time.Unix(int64(r.CompletedAt), 0)
	started := time.Unix(int64(r.StartedAt), 0)
	_, err = d.Exec(`
UPDATE subagent_runs
SET state = $1, summary = $2, structured_payload = $3,
    error_classification = $4, error_message = $5,
    usage_metadata = $6, tool_execution_summary = $7,
    result_hash = $8, started_at = $9, completed_at = $10, updated_at = now()
WHERE subagent_id = $11`,
		string(r.TerminalState), r.Summary, string(structured),
		r.ErrorClassification, r.ErrorMessage,
		string(usage), string(tools), r.ResultHash,
		started, completed, subagentID)
	return err
}

// ---- Query + recovery ----

// GetSubagent returns one ledger row by subagent id.
func (d *DB) GetSubagent(subagentID string) (*SubagentRun, error) {
	row := d.QueryRow(`
SELECT id, subagent_id, parent_session_id, parent_task_id, correlation_id,
       goal, context, role, model, provider, allowed_toolsets, metadata,
       state, depth, started_at, completed_at, summary, structured_payload,
       error_classification, error_message, usage_metadata, tool_execution_summary,
       result_hash, created_at, updated_at
FROM subagent_runs WHERE subagent_id = $1`, subagentID)
	return scanSubagent(row)
}

// ListSubagents returns the most recent subagent ledger rows for a parent
// session (or the whole ledger when parentSessionID is empty).
func (d *DB) ListSubagents(parentSessionID string, limit int) ([]SubagentRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`
SELECT id, subagent_id, parent_session_id, parent_task_id, correlation_id,
       goal, context, role, model, provider, allowed_toolsets, metadata,
       state, depth, started_at, completed_at, summary, structured_payload,
       error_classification, error_message, usage_metadata, tool_execution_summary,
       result_hash, created_at, updated_at
FROM subagent_runs
WHERE ($1 = '' OR parent_session_id = $1)
ORDER BY created_at DESC
LIMIT $2`, parentSessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubagentRun{}
	for rows.Next() {
		s, err := scanSubagent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// RecoverStuckSubagents marks ledger rows left in a non-terminal state by a
// crash/restart as INTERRUPTED. Returns the number of rows recovered. This is
// the "restart recovery" half of the ledger: in-memory children die with the
// process, so any PENDING/STARTING/RUNNING/CANCEL_REQUESTED row is orphaned.
func (d *DB) RecoverStuckSubagents() (int64, error) {
	res, err := d.Exec(`
UPDATE subagent_runs
SET state = 'INTERRUPTED',
    error_classification = 'INTERRUPTED',
    error_message = 'interrupted by process restart',
    completed_at = COALESCE(completed_at, now()),
    updated_at = now()
WHERE state IN ('PENDING','STARTING','RUNNING','CANCEL_REQUESTED')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- helpers ----

func mapOrEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func scanSubagent(row interface{ Scan(...any) error }) (*SubagentRun, error) {
	var s SubagentRun
	var tools, meta, structured, usage, toolsum string
	var startedAt, completedAt, createdAt, updatedAt time.Time
	var started, completed sql.NullTime
	err := row.Scan(&s.ID, &s.SubagentID, &s.ParentSessionID, &s.ParentTaskID,
		&s.CorrelationID, &s.Goal, &s.Context, &s.Role, &s.Model, &s.Provider,
		&tools, &meta, &s.State, &s.Depth,
		&started, &completed, &s.Summary, &structured,
		&s.ErrorClassification, &s.ErrorMessage, &usage, &toolsum,
		&s.ResultHash, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	s.AllowedToolsets = splitJSONSlice(tools)
	s.Metadata = parseJSONMap(meta)
	s.StructuredPayload = parseJSONMap(structured)
	s.UsageMetadata = parseJSONMap(usage)
	s.ToolExecutionSummary = parseJSONMap(toolsum)
	if started.Valid {
		startedAt = started.Time
		s.StartedAt = &startedAt
	}
	if completed.Valid {
		completedAt = completed.Time
		s.CompletedAt = &completedAt
	}
	s.CreatedAt = createdAt
	s.UpdatedAt = updatedAt
	return &s, nil
}

func splitJSONSlice(raw string) []string {
	var out []string
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func parseJSONMap(raw string) map[string]any {
	out := map[string]any{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}
