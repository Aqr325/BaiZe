package db

import (
	"fmt"
	"time"
)

// Constraint is one operator-authored operation constraint for a task: kind=allow
// (permitted operations) or kind=deny (forbidden operations), free-text. Stored in
// task_constraints, keyed by exploration_id (cascades with the exploration).
//
// Fence 升级后，约束可携带结构化字段（match/pattern），使边界可机器判定：
//   - Match  非空时该规则是结构化规则（作用于 tool|command|host|path|port|all 表面）。
//   - Pattern 是该表面上的 glob。
//   - Match/Pattern 均为空时是自由文本规则（旧行为：仅注入提示词走 AI 自检）。
type Constraint struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"` // allow | deny
	Text      string    `json:"text"`
	Origin    string    `json:"origin,omitempty"` // goals | human | system
	Match     *string   `json:"match,omitempty"`  // tool|command|host|path|port|all; nil=自由文本
	Pattern   *string   `json:"pattern,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Structured reports whether this rule is machine-checkable (Fence 规则)。
func (c Constraint) Structured() bool {
	return c.Match != nil && *c.Match != "" && c.Pattern != nil && *c.Pattern != ""
}

// ListConstraints returns this exploration's constraints, allow before deny, oldest
// first within each group (stable render order for the prompt block + UI).
func (s *ExplorationStore) ListConstraints() ([]Constraint, error) {
	rows, err := s.db.Query(`
SELECT id, kind, text, COALESCE(origin,''), match, pattern, created_at
FROM task_constraints WHERE exploration_id=$1
ORDER BY (kind='deny'), id`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Constraint
	for rows.Next() {
		var c Constraint
		if err := rows.Scan(&c.ID, &c.Kind, &c.Text, &c.Origin, &c.Match, &c.Pattern, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddConstraint inserts one free-text constraint (kind must be allow|deny) and
// returns its id. match/pattern 留空即自由文本规则。
func (s *ExplorationStore) AddConstraint(kind, text, origin string) (int64, error) {
	return s.AddStructuredConstraint(kind, text, "", "", origin)
}

// AddStructuredConstraint inserts one constraint with optional structured fence
// fields. match/pattern 为空表示自由文本（旧行为）。
func (s *ExplorationStore) AddStructuredConstraint(kind, text, match, pattern, origin string) (int64, error) {
	if kind != "allow" && kind != "deny" {
		return 0, fmt.Errorf("kind 必须是 allow 或 deny")
	}
	if origin == "" {
		origin = "system"
	}
	var mp, pp *string
	if match != "" {
		mp = &match
	}
	if pattern != "" {
		pp = &pattern
	}
	var id int64
	err := s.db.QueryRow(`
INSERT INTO task_constraints(exploration_id, kind, text, origin, match, pattern)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, s.expID, kind, text, origin, mp, pp).Scan(&id)
	return id, err
}

// UpdateStructuredConstraint rewrites a constraint's kind + text + structured
// fence fields. match/pattern 为空会清空结构化（转回自由文本）。
func (s *ExplorationStore) UpdateStructuredConstraint(id int64, kind, text, match, pattern string) error {
	if kind != "allow" && kind != "deny" {
		return fmt.Errorf("kind 必须是 allow 或 deny")
	}
	var mp, pp *string
	if match != "" {
		mp = &match
	}
	if pattern != "" {
		pp = &pattern
	}
	res, err := s.db.Exec(`
UPDATE task_constraints SET kind=$1, text=$2, match=$3, pattern=$4, updated_at=now()
WHERE id=$5 AND exploration_id=$6`, kind, text, mp, pp, id, s.expID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("约束不存在")
	}
	return nil
}

// DeleteConstraint removes a constraint; scoped to this exploration. Returns an
// error if no such constraint exists.
func (s *ExplorationStore) DeleteConstraint(id int64) error {
	res, err := s.db.Exec(`DELETE FROM task_constraints WHERE id=$1 AND exploration_id=$2`, id, s.expID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("约束不存在")
	}
	return nil
}

// --- Fence 越界授权存储 ---

// FenceAuthz is one 越界授权 record: an out-of-bounds call that a human approved.
type FenceAuthz struct {
	ID          int64      `json:"id"`
	Surface     string     `json:"surface"`
	Tool        string     `json:"tool,omitempty"`
	InputDigest string     `json:"input_digest,omitempty"`
	GrantedBy   string     `json:"granted_by,omitempty"`
	Note        string     `json:"note,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ListFenceAuthz returns this exploration's 越界授权 records, newest first.
func (s *ExplorationStore) ListFenceAuthz() ([]FenceAuthz, error) {
	rows, err := s.db.Query(`
SELECT id, surface, COALESCE(tool,''), COALESCE(input_digest,''), COALESCE(granted_by,''),
       COALESCE(note,''), created_at, expires_at
FROM task_fence_authz WHERE exploration_id=$1 ORDER BY id DESC`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FenceAuthz
	for rows.Next() {
		var a FenceAuthz
		if err := rows.Scan(&a.ID, &a.Surface, &a.Tool, &a.InputDigest, &a.GrantedBy, &a.Note, &a.CreatedAt, &a.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// IsFenceAuthorized reports whether `surface` has a live (unexpired) 越界授权.
func (s *ExplorationStore) IsFenceAuthorized(surface string) bool {
	var one int
	err := s.db.QueryRow(`
SELECT 1 FROM task_fence_authz
WHERE exploration_id=$1 AND surface=$2
  AND (expires_at IS NULL OR expires_at > now())
LIMIT 1`, s.expID, surface).Scan(&one)
	return err == nil
}

// AddFenceAuthz records a 越界授权 for `surface`; digest is an optional sha256 of
// the first authorized input. Returns the record id.
func (s *ExplorationStore) AddFenceAuthz(surface, tool, inputDigest, grantedBy, note string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`
INSERT INTO task_fence_authz(exploration_id, surface, tool, input_digest, granted_by, note)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		s.expID, surface, tool, inputDigest, grantedBy, note).Scan(&id)
	return id, err
}

// DeleteFenceAuthz removes a 越界授权; scoped to this exploration.
func (s *ExplorationStore) DeleteFenceAuthz(id int64) error {
	res, err := s.db.Exec(`DELETE FROM task_fence_authz WHERE id=$1 AND exploration_id=$2`, id, s.expID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("授权不存在")
	}
	return nil
}
