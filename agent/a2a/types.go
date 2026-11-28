// Package a2a implements a pragmatic subset of the A2A (Agent-to-Agent)
// protocol for cross-gateway Group Chat peer members.
//
// Scope: synchronous JSON-RPC 2.0 over a single HTTP endpoint, carrying the
// task/send method. A peer gateway advertises an AgentCard, receives a
// Message, executes its local Bot, and returns a Task with text artifacts.
// Streaming (SSE) and the long-running task methods (task/get, task/cancel,
// tasks/list) are out of scope for the first cross-gateway cut.
package a2a

import "encoding/json"

// JSON-RPC method names (A2A).
const (
	MethodSendTask = "task/send"
)

// ---- AgentCard -----------------------------------------------------------

// AgentCard advertises a gateway's agent capabilities (A2A AgentCard).
type AgentCard struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	URL         string  `json:"url,omitempty"`
	Version     string  `json:"version,omitempty"`
	Skills      []Skill `json:"skills,omitempty"`
}

// Skill is one advertised agent capability.
type Skill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ---- Message / Part ------------------------------------------------------

// Part kinds.
const (
	PartText = "text"
	PartData = "data"
	PartFile = "file"
)

// Part is one message part. Exactly one of Text/Data/File is set by Kind.
type Part struct {
	Kind     string         `json:"kind"`
	Text     string         `json:"text,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	FileName string         `json:"fileName,omitempty"`
	MimeType string         `json:"mimeType,omitempty"`
}

// Message is a peer-to-peer message.
type Message struct {
	Role  string `json:"role"` // "user" | "agent"
	Parts []Part `json:"parts"`
}

// Text returns the concatenated text parts.
func (m Message) Text() string {
	out := ""
	for _, p := range m.Parts {
		if p.Kind == PartText {
			out += p.Text
		}
	}
	return out
}

// ---- Task ----------------------------------------------------------------

// Task states (A2A).
const (
	TaskStateSubmitted = "submitted"
	TaskStateWorking   = "working"
	TaskStateCompleted = "completed"
	TaskStateFailed    = "failed"
	TaskStateCancelled = "cancelled"
)

// Task is the response of a task/send call.
type Task struct {
	ID        string     `json:"id"`
	State     string     `json:"state"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	Message   *Message   `json:"message,omitempty"`
}

// Artifact is a task output (text artifact carries the Bot's reply).
type Artifact struct {
	Name     string `json:"name,omitempty"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// ---- JSON-RPC 2.0 envelope ----------------------------------------------

// request is the JSON-RPC request envelope.
type request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      any              `json:"id"`
	Method  string           `json:"method"`
	Params  *json.RawMessage `json:"params,omitempty"`
}

// response is the JSON-RPC response envelope.
type response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// sendParams is the task/send params: the caller's card plus the message.
type sendParams struct {
	Card    AgentCard `json:"card,omitempty"`
	Message Message   `json:"message"`
}
