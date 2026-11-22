package delegation

import (
	"context"
)

// ChildConfig is the immutable input one child run receives. It carries the
// route/model the parent resolved plus the restricted toolset.
type ChildConfig struct {
	SubagentID      string
	Goal            string
	Context         string
	Role            string
	Model           string
	Provider        string
	AllowedToolsets []string
	Metadata        map[string]any
}

// ChildOutcome is the bounded result one child turn produces. It mirrors the
// bounded receipt fields hermes' run_child_lifecycle returns (status, summary,
// error, api_calls, duration_seconds) plus a structured payload.
type ChildOutcome struct {
	Status              string         // "completed" | "interrupted" | "error"
	Summary             string
	Error               string
	StructuredPayload   map[string]any
	UsageMetadata       map[string]any
	ToolExecutionSummary map[string]any
}

// Emit is the per-child event sink: kind + payload. The child calls it for
// delta / tool.start / tool.complete / activity frames.
type Emit func(kind EventKind, payload map[string]any)

// TurnFn runs one child agent turn. The real implementation is wired from the
// agent package (it builds a restricted ToolSet + agentcore session); tests
// inject a fake.
type TurnFn func(ctx context.Context, cfg ChildConfig, emit Emit) (ChildOutcome, error)

// NewChildRunner wraps a TurnFn into a Runner that publishes events to a broker
// (nil broker disables publishing). This keeps event fan-out in the delegation
// package and the agent-turn mechanics in the agent package.
func NewChildRunner(turn TurnFn, broker *Broker) Runner {
	return func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		return turn(ctx, cfg, func(kind EventKind, payload map[string]any) {
			if broker != nil {
				broker.Publish(Event{Kind: kind, SubagentID: cfg.SubagentID, Ts: now(), Data: payload})
			}
		})
	}
}
