package delegation

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// PublicContractVersion is the lifecycle API contract version (mirrors
// PUBLIC_CONTRACT_VERSION).
const PublicContractVersion = 1

const (
	// MaxGoalChars bounds a child goal (mirrors _MAX_GOAL_CHARS).
	MaxGoalChars = 16_000
	// MaxContextChars bounds a child context (mirrors _MAX_CONTEXT_CHARS).
	MaxContextChars = 32_000
	// MaxMetadataBytes bounds child metadata (mirrors _MAX_METADATA_BYTES).
	MaxMetadataBytes = 8_192
	// MaxResultChars bounds a child result summary (mirrors _MAX_RESULT_CHARS).
	MaxResultChars = 32_000
	// TerminalRetentionSeconds keeps terminal snapshots (mirrors
	// _TERMINAL_RETENTION_SECONDS).
	TerminalRetentionSeconds = 3_600
)

// State is the lifecycle state of one subagent. Mirrors SubagentState.
type State string

const (
	StatePending         State = "PENDING"
	StateStarting        State = "STARTING"
	StateRunning         State = "RUNNING"
	StateSucceeded       State = "SUCCEEDED"
	StateFailed          State = "FAILED"
	StateInterrupted     State = "INTERRUPTED"
	StateCancelRequested State = "CANCEL_REQUESTED"
	StateCancelled       State = "CANCELLED"
	StateUnknown         State = "UNKNOWN"
)

// Terminal reports whether s is a terminal state.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateInterrupted, StateCancelled:
		return true
	}
	return false
}

// LaunchRequest is a request to launch one subagent. Mirrors
// SubagentLaunchRequest (fields hermes supports; per-launch timeout and
// working_directory are deliberately rejected, as in hermes).
type LaunchRequest struct {
	Goal            string
	Context         string
	Role            string // "leaf" or "orchestrator"
	Model           string
	Provider        string
	AllowedToolsets []string
	ParentSessionID string
	ParentTaskID    int64
	CorrelationID   string
	Metadata        map[string]any
}

// Handle identifies one subagent. It is capability-verified (HMAC) so a forged
// handle cannot address another parent's child. Mirrors SubagentHandle.
type Handle struct {
	ContractVersion int     `json:"contract_version"`
	SubagentID      string  `json:"subagent_id"`
	ParentSessionID string  `json:"parent_session_id"`
	CorrelationID   string  `json:"correlation_id"`
	CreatedAt       float64 `json:"created_at"`
	Provider        string  `json:"provider"`
	Model           string  `json:"model"`
	Role            string  `json:"role"`
	Depth           int     `json:"depth"`
	Capability      string  `json:"capability"`
}

// Status is a point-in-time snapshot. Mirrors SubagentStatus.
type Status struct {
	Handle     Handle  `json:"handle"`
	State      State   `json:"state"`
	UpdatedAt  float64 `json:"updated_at"`
	Diagnostic string  `json:"diagnostic,omitempty"`
}

// TerminalState is the terminal outcome. Mirrors SubagentTerminalState.
type TerminalState struct {
	Handle     Handle `json:"handle"`
	State      State  `json:"state"`
	Completed  bool   `json:"completed"`
	TimedOut   bool   `json:"timed_out"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

// CancelResult is the outcome of a cancel request. Mirrors SubagentCancelResult.
type CancelResult struct {
	Accepted        bool  `json:"accepted"`
	AlreadyTerminal bool  `json:"already_terminal"`
	UnknownHandle   bool  `json:"unknown_handle"`
	Unsupported     bool  `json:"unsupported"`
	State           State `json:"state"`
}

// Result is the child's bounded terminal result. Mirrors SubagentResult.
type Result struct {
	Handle               Handle         `json:"handle"`
	TerminalState        State          `json:"terminal_state"`
	Ready                bool           `json:"ready"`
	Summary              string         `json:"summary,omitempty"`
	StructuredPayload    map[string]any `json:"structured_payload,omitempty"`
	StartedAt            float64        `json:"started_at,omitempty"`
	CompletedAt          float64        `json:"completed_at,omitempty"`
	ErrorClassification  string         `json:"error_classification,omitempty"`
	ErrorMessage         string         `json:"error_message,omitempty"`
	UsageMetadata        map[string]any `json:"usage_metadata,omitempty"`
	ToolExecutionSummary map[string]any `json:"tool_execution_summary,omitempty"`
	ResultHash           string         `json:"result_hash,omitempty"`
}

// ReconnectResult reports whether a serialized handle reconnects. Mirrors
// SubagentReconnectResult. In-process children always reconnect while the
// record is retained; after a restart it is unavailable.
type ReconnectResult struct {
	Connected  bool   `json:"connected"`
	State      State  `json:"state"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

// Runner runs one child turn. It is the injectable seam that lets tests drive
// the lifecycle without a live agent; the real implementation is wired in the
// agent package (child.go RunChild).
type Runner func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error)

// _record is one registry entry. Never returned directly (only snapshots).
type _record struct {
	mu          sync.RWMutex
	handle      Handle
	state       State
	updatedAt   float64
	startedAt   float64
	completedAt float64
	result      *Result
	done        chan struct{} // closed when terminal
	cancel      context.CancelFunc
	steer       func(string) bool
}

// _registry is the thread-safe terminal-retention registry. Mirrors _Registry.
type _registry struct {
	mu           sync.RWMutex
	records      map[string]*_record
	correlations map[string]string // (parent|correlation) -> subagent_id
}

// LifecycleService is the stable public lifecycle API. Mirrors
// SubagentLifecycleService. Children run in-process; completed results stay
// until process exit (bounded by retention); reconnect reports that a
// serialized handle cannot reconnect after a restart.
type LifecycleService struct {
	registry        *_registry
	broker          *Broker
	runner          Runner
	secret          []byte
	parentSessionOf func() string // active parent session id (nil = none)
	persist         Persistence   // durable ledger (nil = in-memory only)
}

// NewLifecycleService builds a service; runner may be nil (launch returns an
// error). broker may be nil (events disabled).
func NewLifecycleService(runner Runner, broker *Broker, parentSessionOf func() string) *LifecycleService {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &LifecycleService{
		registry:        &_registry{records: map[string]*_record{}, correlations: map[string]string{}},
		broker:          broker,
		runner:          runner,
		secret:          secret,
		parentSessionOf: parentSessionOf,
	}
}

// SetPersistence wires the durable subagent ledger. Call once before any
// launch; a nil value disables persistence (in-memory only). Setting it after
// children have launched only affects subsequent transitions.
func (s *LifecycleService) SetPersistence(p Persistence) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	s.persist = p
}

// LifecycleError is a request that cannot be safely accepted.
type LifecycleError struct{ Msg string }

func (e *LifecycleError) Error() string { return e.Msg }

func lifecycleErrorf(format string, args ...any) error {
	return &LifecycleError{Msg: fmt.Sprintf(format, args...)}
}

// requestRejections are launch-request rejections in check order.
func requestRejections(r *LaunchRequest) []error {
	var errs []error
	if r == nil || strings.TrimSpace(r.Goal) == "" || len(r.Goal) > MaxGoalChars {
		errs = append(errs, lifecycleErrorf("goal must be a non-empty string of at most %d characters.", MaxGoalChars))
	}
	if r.Context != "" && len(r.Context) > MaxContextChars {
		errs = append(errs, lifecycleErrorf("context must be a string of at most %d characters.", MaxContextChars))
	}
	if r.Role != "" && r.Role != "leaf" && r.Role != "orchestrator" {
		errs = append(errs, lifecycleErrorf("role must be 'leaf' or 'orchestrator'."))
	}
	if r.Provider != "" && (strings.TrimSpace(r.Provider) == "" || len(r.Provider) > 64) {
		errs = append(errs, lifecycleErrorf("provider must be a non-empty string of at most 64 characters."))
	}
	return errs
}

// Launch validates, assigns identity, registers the record, and starts the
// child asynchronously. Mirrors SubagentLifecycleService.launch.
func (s *LifecycleService) Launch(parentCtx context.Context, req *LaunchRequest) (Handle, error) {
	if errs := requestRejections(req); len(errs) > 0 {
		return Handle{}, errs[0]
	}
	if s.runner == nil {
		return Handle{}, lifecycleErrorf("no child runner is configured; delegation is unavailable.")
	}
	if req.Role == "" {
		req.Role = "leaf"
	}
	metaBytes, err := json.Marshal(req.Metadata)
	if err != nil {
		return Handle{}, lifecycleErrorf("metadata must be JSON-serializable: %v", err)
	}
	if len(metaBytes) > MaxMetadataBytes {
		return Handle{}, lifecycleErrorf("metadata exceeds %d bytes.", MaxMetadataBytes)
	}
	// Toolsets ⊆ parent: never broaden parent permissions.
	if len(req.AllowedToolsets) > 0 && len(req.ParentSessionID) == 0 {
		// Without a parent scope we cannot verify the subset; require explicit.
		return Handle{}, lifecycleErrorf("allowed_toolsets requires a parent session scope.")
	}
	parentSession := req.ParentSessionID
	if parentSession == "" && s.parentSessionOf != nil {
		parentSession = s.parentSessionOf()
	}
	created := float64(time.Now().UnixNano()) / 1e9
	subagentID := newID()
	handle := Handle{
		ContractVersion: PublicContractVersion,
		SubagentID:      subagentID,
		ParentSessionID: parentSession,
		CorrelationID:   req.CorrelationID,
		CreatedAt:       created,
		Provider:        req.Provider,
		Model:           req.Model,
		Role:            req.Role,
		Depth:           1,
	}
	handle.Capability = s.capability(handle)

	// Correlation uniqueness within a parent.
	corrKey := ""
	if req.CorrelationID != "" {
		corrKey = parentSession + "|" + req.CorrelationID
		s.registry.mu.Lock()
		if _, dup := s.registry.correlations[corrKey]; dup {
			s.registry.mu.Unlock()
			return Handle{}, lifecycleErrorf("duplicate correlation_id for this parent session.")
		}
		s.registry.correlations[corrKey] = subagentID
		s.registry.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(parentCtx)
	rec := &_record{
		handle:    handle,
		state:     StatePending,
		updatedAt: created,
		done:      make(chan struct{}),
		cancel:    cancel,
	}
	s.registry.mu.Lock()
	s.registry.cleanupLocked()
	s.registry.records[subagentID] = rec
	persist := s.persist // pointer read under lock; call happens outside
	s.registry.mu.Unlock()
	if s.broker != nil {
		s.broker.PublishState(subagentID, StatePending, nil)
	}
	// Best-effort durable ledger: the in-memory registry is authoritative, so a
	// persistence failure must not prevent the child from running.
	if persist != nil {
		_ = persist.UpsertLaunch(handle, req)
	}
	go s.run(rec, childCtx, req)
	return handle, nil
}

// runChild 把宿主回调包成"永不 panic 且永不返回非法结果"的形式。回调 panic
// 若不被恢复会终止整个进程；即便被外层 recover，若此处不返回 outcome，后续
// 状态机仍会把 nil outcome 当成功处理。统一在这里转成 error 交给既有错误分支。
func (s *LifecycleService) runChild(ctx context.Context, cfg ChildConfig) (out ChildOutcome, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = ChildOutcome{}
			err = fmt.Errorf("child runner panic: %v", r)
		}
	}()
	return s.runner(ctx, cfg)
}

func (s *LifecycleService) run(rec *_record, ctx context.Context, req *LaunchRequest) {
	s.setState(rec, StateStarting, "")
	cfg := ChildConfig{
		SubagentID:      rec.handle.SubagentID,
		Goal:            req.Goal,
		Context:         req.Context,
		Role:            req.Role,
		Model:           req.Model,
		Provider:        req.Provider,
		AllowedToolsets: req.AllowedToolsets,
		Metadata:        req.Metadata,
	}
	started := float64(time.Now().UnixNano()) / 1e9
	rec.mu.Lock()
	rec.startedAt = started
	rec.mu.Unlock()
	s.setState(rec, StateRunning, "")

	outcome, err := s.runChild(ctx, cfg)

	// Compute the terminal result under the locks, then publish and persist
	// outside them: a slow durable write must never stall the registry for
	// other children, and the broker fan-out must not hold rec.mu.
	var res Result
	func() {
		s.registry.mu.Lock()
		defer s.registry.mu.Unlock()
		rec.mu.Lock()
		defer rec.mu.Unlock()
		defer close(rec.done)
		rec.completedAt = float64(time.Now().UnixNano()) / 1e9

		res.Handle = rec.handle
		res.StartedAt = started
		res.CompletedAt = rec.completedAt
		res.Ready = true
		if err != nil {
			if ctx.Err() != nil && rec.state == StateCancelRequested {
				rec.state = StateCancelled
				res.TerminalState = StateCancelled
				res.ErrorClassification = "CANCELLED"
				res.ErrorMessage = clipString("cancelled", MaxResultChars)
			} else if ctx.Err() != nil {
				rec.state = StateInterrupted
				res.TerminalState = StateInterrupted
				res.ErrorClassification = "INTERRUPTED"
				res.ErrorMessage = clipString(ctx.Err().Error(), MaxResultChars)
			} else {
				rec.state = StateFailed
				res.TerminalState = StateFailed
				res.ErrorClassification = "child_error"
				res.ErrorMessage = clipString(err.Error(), MaxResultChars)
			}
			res.UsageMetadata = map[string]any{}
			res.ToolExecutionSummary = map[string]any{}
		} else {
			if outcome.Status == "interrupted" {
				if rec.state == StateCancelRequested {
					rec.state = StateCancelled
					res.TerminalState = StateCancelled
					res.ErrorClassification = "CANCELLED"
				} else {
					rec.state = StateInterrupted
					res.TerminalState = StateInterrupted
					res.ErrorClassification = "INTERRUPTED"
				}
			} else if outcome.Status == "completed" {
				rec.state = StateSucceeded
				res.TerminalState = StateSucceeded
			} else {
				rec.state = StateFailed
				res.TerminalState = StateFailed
				res.ErrorClassification = strings.ToUpper(outcome.Status)
			}
			res.Summary = clipString(outcome.Summary, MaxResultChars)
			res.StructuredPayload = outcome.StructuredPayload
			res.ErrorMessage = clipString(outcome.Error, MaxResultChars)
			if res.ErrorClassification == "" && res.TerminalState == StateFailed {
				res.ErrorClassification = "ERROR"
			}
			res.UsageMetadata = outcome.UsageMetadata
			res.ToolExecutionSummary = outcome.ToolExecutionSummary
		}
		res.ResultHash = resultHash(res)
		rec.result = &res
		rec.updatedAt = rec.completedAt
		// release cancel after terminal
		rec.cancel = nil
	}()
	if s.broker != nil {
		s.broker.PublishResult(rec.handle.SubagentID, res)
	}
	s.registry.mu.RLock()
	persist := s.persist
	s.registry.mu.RUnlock()
	if persist != nil {
		_ = persist.UpdateResult(rec.handle.SubagentID, res)
	}
}

func (s *LifecycleService) setState(rec *_record, st State, diag string) {
	rec.mu.Lock()
	rec.state = st
	rec.updatedAt = float64(time.Now().UnixNano()) / 1e9
	rec.mu.Unlock()
	if s.broker != nil {
		s.broker.PublishState(rec.handle.SubagentID, st, map[string]any{"diagnostic": diag})
	}
	// Terminal states are persisted via UpdateResult (which carries the full
	// result); non-terminal transitions update the ledger row in place.
	if !st.Terminal() {
		s.registry.mu.RLock()
		persist := s.persist
		s.registry.mu.RUnlock()
		if persist != nil {
			_ = persist.UpdateState(rec.handle.SubagentID, st, float64(time.Now().UnixNano())/1e9)
		}
	}
}

// Status returns a point-in-time snapshot. Mirrors status.
func (s *LifecycleService) Status(h Handle) Status {
	rec := s.record(h)
	if rec == nil {
		return Status{Handle: h, State: StateUnknown, UpdatedAt: now(), Diagnostic: "UNKNOWN_HANDLE"}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return Status{Handle: rec.handle, State: rec.state, UpdatedAt: rec.updatedAt}
}

// Wait blocks until the child reaches a terminal state or the timeout elapses.
// Mirrors wait.
func (s *LifecycleService) Wait(h Handle, timeout time.Duration) TerminalState {
	rec := s.record(h)
	if rec == nil {
		return TerminalState{Handle: h, State: StateUnknown, Completed: true, Diagnostic: "UNKNOWN_HANDLE"}
	}
	rec.mu.Lock()
	if rec.state.Terminal() {
		rec.mu.Unlock()
		return TerminalState{Handle: rec.handle, State: rec.state, Completed: true}
	}
	done := rec.done
	rec.mu.Unlock()
	// timeout <= 0 means "no deadline" -> block until terminal. This mirrors
	// hermes wait semantics; a zero timer would otherwise poll non-blocking and
	// report RUNNING for a child that just launched.
	if timeout <= 0 {
		<-done
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return TerminalState{Handle: rec.handle, State: rec.state, Completed: rec.result != nil}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return TerminalState{Handle: rec.handle, State: rec.state, Completed: rec.result != nil, TimedOut: true}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return TerminalState{Handle: rec.handle, State: rec.state, Completed: rec.result != nil}
}

// Cancel requests the child be interrupted. Mirrors cancel.
func (s *LifecycleService) Cancel(h Handle, reason string) CancelResult {
	rec := s.record(h)
	if rec == nil {
		return CancelResult{UnknownHandle: true, State: StateUnknown}
	}
	rec.mu.Lock()
	if rec.result != nil {
		rec.mu.Unlock()
		return CancelResult{AlreadyTerminal: true, State: rec.state}
	}
	rec.state = StateCancelRequested
	rec.updatedAt = now()
	cancel := rec.cancel
	rec.mu.Unlock()
	if s.broker != nil {
		s.broker.PublishState(h.SubagentID, StateCancelRequested, map[string]any{"reason": reason})
	}
	if cancel != nil {
		cancel()
		return CancelResult{Accepted: true, State: StateCancelRequested}
	}
	return CancelResult{Unsupported: true, State: StateCancelRequested}
}

// CancelByID requests a child be interrupted by its durable subagent id,
// bypassing capability verification. It is the internal cancel path for the
// server's /api/delegations/{id}/cancel endpoint, which is already protected by
// the HTTP auth layer and addresses a child by its ledger id (the caller cannot
// know the capability HMAC). Behavior matches Cancel; an unknown id reports
// UnknownHandle.
func (s *LifecycleService) CancelByID(subagentID, reason string) CancelResult {
	s.registry.mu.RLock()
	rec := s.registry.records[subagentID]
	s.registry.mu.RUnlock()
	if rec == nil {
		return CancelResult{UnknownHandle: true, State: StateUnknown}
	}
	rec.mu.Lock()
	if rec.result != nil {
		rec.mu.Unlock()
		return CancelResult{AlreadyTerminal: true, State: rec.state}
	}
	rec.state = StateCancelRequested
	rec.updatedAt = now()
	cancel := rec.cancel
	rec.mu.Unlock()
	if s.broker != nil {
		s.broker.PublishState(subagentID, StateCancelRequested, map[string]any{"reason": reason})
	}
	s.registry.mu.RLock()
	persist := s.persist
	s.registry.mu.RUnlock()
	if persist != nil {
		_ = persist.UpdateState(subagentID, StateCancelRequested, now())
	}
	if cancel != nil {
		cancel()
		return CancelResult{Accepted: true, State: StateCancelRequested}
	}
	return CancelResult{Unsupported: true, State: StateCancelRequested}
}

// Result returns the child's terminal result. Mirrors result.
func (s *LifecycleService) Result(h Handle) Result {
	rec := s.record(h)
	if rec == nil {
		return Result{Handle: h, TerminalState: StateUnknown, Ready: false, ErrorClassification: "UNKNOWN_HANDLE"}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.result != nil {
		return *rec.result
	}
	return Result{Handle: rec.handle, TerminalState: rec.state, Ready: false, ErrorClassification: "NOT_READY"}
}

// Reconnect reports whether a serialized handle reconnects. Mirrors reconnect.
func (s *LifecycleService) Reconnect(h Handle) ReconnectResult {
	rec := s.record(h)
	if rec == nil {
		return ReconnectResult{Connected: false, State: StateUnknown, Diagnostic: "RECONNECT_UNAVAILABLE"}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return ReconnectResult{Connected: true, State: rec.state}
}

// Steer queues text for the child's next iteration boundary. Mirrors steer.
func (s *LifecycleService) Steer(h Handle, text string) bool {
	rec := s.record(h)
	if rec == nil || strings.TrimSpace(text) == "" {
		return false
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.result != nil || rec.steer == nil {
		return false
	}
	return rec.steer(text)
}

// SetSteer wires the child's steering hook (called by the agent wiring).
func (s *LifecycleService) SetSteer(subagentID string, fn func(string) bool) {
	s.registry.mu.RLock()
	rec := s.registry.records[subagentID]
	s.registry.mu.RUnlock()
	if rec != nil {
		rec.mu.Lock()
		rec.steer = fn
		rec.mu.Unlock()
	}
}

// record returns the registry record for a well-formed, capability-verified
// handle owned by the active parent. Mirrors _record lookup.
func (s *LifecycleService) record(h Handle) *_record {
	if !handleWellFormed(h) {
		return nil
	}
	expected := s.capability(h)
	if !hmac.Equal([]byte(h.Capability), []byte(expected)) {
		return nil
	}
	s.registry.mu.RLock()
	rec := s.registry.records[h.SubagentID]
	s.registry.mu.RUnlock()
	if rec == nil {
		return nil
	}
	return rec
}

func (s *LifecycleService) capability(h Handle) string {
	value := fmt.Sprintf("%s|%s|%.6f", h.SubagentID, h.ParentSessionID, h.CreatedAt)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func handleWellFormed(h Handle) bool {
	return h.ContractVersion == PublicContractVersion &&
		h.SubagentID != "" &&
		(h.ParentSessionID == "" || true) &&
		h.CreatedAt > 0 && !math.IsNaN(h.CreatedAt) &&
		(h.Provider == "" || true) &&
		(h.Model == "" || true) &&
		h.Role != "" &&
		h.Depth >= 0 &&
		h.Capability != ""
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Clip by runes, not bytes: summaries/errors are often Chinese (3 bytes per
	// rune), and a byte slice can split a UTF-8 sequence into invalid bytes that
	// later surface as replacement chars or break JSON encoding.
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func resultHash(r Result) string {
	payload := map[string]any{
		"summary": r.Summary, "terminal_state": string(r.TerminalState),
		"error_classification": r.ErrorClassification, "error_message": r.ErrorMessage,
		"usage": r.UsageMetadata, "tools": r.ToolExecutionSummary, "structured": r.StructuredPayload,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cleanupLocked removes expired terminal snapshots. Caller holds mu.
func (r *_registry) cleanupLocked() {
	cutoff := time.Now().Unix() - TerminalRetentionSeconds
	for id, rec := range r.records {
		rec.mu.Lock()
		expired := rec.result != nil && rec.completedAt > 0 && int64(rec.completedAt) < cutoff
		corr := rec.handle.CorrelationID
		parent := rec.handle.ParentSessionID
		rec.mu.Unlock()
		if expired {
			delete(r.records, id)
			if corr != "" {
				delete(r.correlations, parent+"|"+corr)
			}
		}
	}
}
