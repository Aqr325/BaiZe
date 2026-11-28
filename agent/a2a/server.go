package a2a

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// TaskExecutor runs a peer's message and returns a Task. The server layer wires
// this to a local Bot turn (the peer gateway executes its own member's reply).
type TaskExecutor func(ctx context.Context, card AgentCard, msg Message) (*Task, error)

// Handler serves A2A JSON-RPC requests on a single POST endpoint.
type Handler struct {
	Token    string // required Bearer token ("" = no auth, loopback/dev only)
	Executor TaskExecutor
}

// ServeHTTP implements http.Handler for the A2A JSON-RPC endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponse(w, response{JSONRPC: "2.0", ID: nil, Error: &rpcError{Code: -32600, Message: "method not allowed"}})
		return
	}
	if h.Token != "" && r.Header.Get("Authorization") != "Bearer "+h.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req request
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeResponse(w, response{JSONRPC: "2.0", ID: nil, Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if req.JSONRPC != "2.0" {
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32600, Message: "invalid request"}})
		return
	}
	switch req.Method {
	case MethodSendTask:
		h.handleSendTask(w, r.Context(), req)
	default:
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}})
	}
}

func (h *Handler) handleSendTask(w http.ResponseWriter, ctx context.Context, req request) {
	if req.Params == nil {
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}})
		return
	}
	var p sendParams
	if err := json.Unmarshal(*req.Params, &p); err != nil {
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}})
		return
	}
	if h.Executor == nil {
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "executor not configured"}})
		return
	}
	task, err := h.Executor(ctx, p.Card, p.Message)
	if err != nil {
		writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32000, Message: err.Error()}})
		return
	}
	writeResponse(w, response{JSONRPC: "2.0", ID: req.ID, Result: task})
}

func writeResponse(w http.ResponseWriter, r response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(r)
}
