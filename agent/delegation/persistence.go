package delegation

// Persistence is the durable store for subagent lifecycle records. It mirrors
// the SQLite store hermes' subagent_lifecycle uses to keep a subagent ledger
// across process restarts.
//
// It is implemented by the db layer and wired in by the server; a nil
// Persistence keeps the lifecycle purely in-memory (the default). All methods
// are best-effort: a persistence failure must never fail the child run itself —
// the child's real outcome lives in the in-memory registry regardless.
type Persistence interface {
	// UpsertLaunch records a new subagent before the child starts running.
	UpsertLaunch(h Handle, req *LaunchRequest) error
	// UpdateState records a non-terminal state transition (ts is unix seconds).
	UpdateState(subagentID string, st State, ts float64) error
	// UpdateResult records the child's terminal result.
	UpdateResult(subagentID string, r Result) error
}
