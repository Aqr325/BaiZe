package delegation

import (
	"context"
)

// Scope is the shared state a child execution carries: the parent lineage and a
// frozen snapshot of the delegation config taken at launch time. It mirrors the
// combination of hermes' delegation_context.py (ContextVar child scope, env
// scrubbing, fences) and safe_worker_policy.py (frozen session config snapshot
// bound once before runtime imports). BaiZe carries the same identity in a
// context value rather than an OS process env.
type Scope struct {
	// ParentSessionID is the session that owns this child ("" for root).
	ParentSessionID string
	// ParentTaskID is the PG task the delegation belongs to (0 = none).
	ParentTaskID int64
	// ExecutionID identifies the delegation batch (parent turn).
	ExecutionID string
	// Depth is the delegation nesting depth (root parent = 0).
	Depth int
	// Role is the child role ("leaf" or "orchestrator").
	Role string
	// Config is the frozen delegation config snapshot at launch time. Never
	// mutated after a child starts (a later config edit cannot reshape it).
	Config Config
	// ParentProvider / ParentModel are the parent's route, for label/trace.
	ParentProvider string
	ParentModel    string
}

// scopeKey is the unexported context key for Scope.
type scopeKey struct{}

// WithScope attaches a Scope to ctx for the child execution.
func WithScope(ctx context.Context, s *Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFrom returns the Scope bound to ctx, or nil.
func ScopeFrom(ctx context.Context) *Scope {
	if s, ok := ctx.Value(scopeKey{}).(*Scope); ok {
		return s
	}
	return nil
}

// SnapshotConfig returns a deep copy of a Config, freezing it at delegation
// time. The returned value is safe to hand to a child and mutate independently.
func SnapshotConfig(cfg Config) Config {
	cp := cfg
	cp.DefaultRoute = cfg.DefaultRoute
	cp.Backends = make(map[string]map[string]any, len(cfg.Backends))
	for k, v := range cfg.Backends {
		inner := make(map[string]any, len(v))
		for kk, vv := range v {
			inner[kk] = vv
		}
		cp.Backends[k] = inner
	}
	return cp
}

// ChildScope derives the child's own Scope from the parent's, bumping depth and
// recording the parent lineage. Mirrors a child inheriting the parent scope with
// the delegated_child_context marker.
func ChildScope(parent *Scope, executionID, role string, cfg Config) *Scope {
	depth := 0
	parentSession := ""
	parentTask := int64(0)
	parentProvider := ""
	parentModel := ""
	if parent != nil {
		depth = parent.Depth + 1
		parentSession = parent.ParentSessionID
		if parent.ParentSessionID == "" {
			parentSession = parent.ExecutionID
		}
		parentTask = parent.ParentTaskID
		parentProvider = parent.ParentProvider
		parentModel = parent.ParentModel
	}
	return &Scope{
		ParentSessionID: parentSession,
		ParentTaskID:    parentTask,
		ExecutionID:     executionID,
		Depth:           depth,
		Role:            role,
		Config:          SnapshotConfig(cfg),
		ParentProvider:  parentProvider,
		ParentModel:     parentModel,
	}
}
