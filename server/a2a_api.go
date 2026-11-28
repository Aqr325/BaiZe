package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/Autumn-27/baize/agent/a2a"
)

// a2aHandler serves the cross-gateway A2A JSON-RPC endpoint. Peer gateways call
// it (POST /a2a) to execute a peer Bot turn on this gateway. It is protected by
// its own Bearer token (ARTEX_A2A_TOKEN, "" = loopback/dev only) and is exempt
// from the browser JWT check (requireAuth whitelists /a2a).
func (s *Server) a2aHandler() http.Handler {
	return &a2a.Handler{
		Token:    os.Getenv("ARTEX_A2A_TOKEN"),
		Executor: s.a2aExecutor,
	}
}

// a2aExecutor runs a peer's Bot turn on this gateway and returns a completed
// Task whose text artifact is the Bot's reply.
func (s *Server) a2aExecutor(ctx context.Context, card a2a.AgentCard, msg a2a.Message) (*a2a.Task, error) {
	ca := s.chatAgentRef()
	if ca == nil {
		return nil, errors.New("LLM 未就绪，无法执行 A2A 任务")
	}
	out, err := ca.Chat(ctx, "default", "a2a-"+card.Name, msg.Text(), 8, time.Minute, false, nil)
	if err != nil {
		return nil, err
	}
	return &a2a.Task{
		ID:        "a2a-" + newGroupID(),
		State:     a2a.TaskStateCompleted,
		Artifacts: []a2a.Artifact{{Name: "reply", Text: out, MimeType: "text/plain"}},
	}, nil
}
