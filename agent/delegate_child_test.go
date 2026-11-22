package agent

import (
	"context"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/baize/agent/delegation"
	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/norma/llm"
)

// delegateProvider is a scripted provider that finishes the child turn in one
// step, so the subagent turn completes without touching real network tools.
type delegateProvider struct {
	autoTitleProvider
	reply string
}

func (p *delegateProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if p.reply == "" {
		p.reply = "子代理完成：已产出具体结果。"
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, "end_turn", llm.Usage{}, nil
}

// Stream emits a real text-delta stream so the agent-core loop produces KindText
// events (the same path a live provider takes), then closes with end_turn.
func (p *delegateProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	text := p.reply
	if text == "" {
		text = "子代理完成：已产出具体结果。"
	}
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil) {
			return
		}
	}
}

// TestRunSubagentTurnRunsEndToEnd wires the child runtime globals (as the server
// does in wireDelegation) and runs one real child turn through RunSubagentTurn,
// asserting it reaches "completed" and publishes delta/tool events.
func TestRunSubagentTurnRunsEndToEnd(t *testing.T) {
	// Save + restore the globals RunSubagentTurn reads.
	savedProv, savedStore, savedDir, savedProxy := ChildProviderFor, ChildStore, ChildWorkDir, ChildProxy
	defer func() {
		ChildProviderFor, ChildStore, ChildWorkDir, ChildProxy = savedProv, savedStore, savedDir, savedProxy
	}()

	ChildProviderFor = func(cfg delegation.ChildConfig) (llm.Provider, error) {
		return &delegateProvider{autoTitleProvider: autoTitleProvider{reply: "子代理完成：已产出具体结果。"}}, nil
	}
	ChildStore = func() *db.ExplorationStore { return nil }
	ChildWorkDir = t.TempDir()
	ChildProxy = func() (string, string) { return "", "" }

	var events []delegation.EventKind
	emit := func(kind delegation.EventKind, payload map[string]any) {
		events = append(events, kind)
	}

	out, err := RunSubagentTurn(t.Context(), delegation.ChildConfig{
		SubagentID: "test-sub-1",
		Goal:       "统计当前目录下文件数量并返回结果。",
		Role:       "leaf",
	}, emit)
	if err != nil {
		t.Fatalf("RunSubagentTurn error: %v", err)
	}
	if out.Status != "completed" {
		t.Fatalf("status = %q, want completed (summary=%q err=%q)", out.Status, out.Summary, out.Error)
	}
	if out.Summary == "" {
		t.Fatalf("summary empty; child produced no text")
	}
	// The child working directory must exist under ChildWorkDir/subagents/<id>.
	subDir := filepath.Join(ChildWorkDir, "subagents", "test-sub-1")
	if _, err := os.Stat(subDir); err != nil {
		t.Fatalf("subagent working dir not created: %v", err)
	}
}
