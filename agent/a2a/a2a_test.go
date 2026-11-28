package a2a

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientServerRoundTrip(t *testing.T) {
	executor := func(ctx context.Context, card AgentCard, msg Message) (*Task, error) {
		if msg.Text() != "please review the edge case" {
			t.Fatalf("executor got message %q", msg.Text())
		}
		return &Task{
			ID:    "t-1",
			State: TaskStateCompleted,
			Artifacts: []Artifact{
				{Name: "reply", Text: "the edge case is safe", MimeType: "text/plain"},
			},
		}, nil
	}
	srv := httptest.NewServer(&Handler{Executor: executor})
	defer srv.Close()

	client := NewClient(srv.URL, "")
	task, err := client.SendTask(context.Background(), AgentCard{Name: "peer"}, Message{
		Role:  "agent",
		Parts: []Part{{Kind: PartText, Text: "please review the edge case"}},
	})
	if err != nil {
		t.Fatalf("SendTask err: %v", err)
	}
	if task.ID != "t-1" || task.State != TaskStateCompleted {
		t.Fatalf("task = %+v, want id=t-1 completed", task)
	}
	if len(task.Artifacts) != 1 || task.Artifacts[0].Text != "the edge case is safe" {
		t.Fatalf("artifacts = %+v", task.Artifacts)
	}
}

func TestHandlerRequiresToken(t *testing.T) {
	srv := httptest.NewServer(&Handler{Token: "s3cret", Executor: func(ctx context.Context, c AgentCard, m Message) (*Task, error) {
		return &Task{ID: "t", State: TaskStateCompleted}, nil
	}})
	defer srv.Close()

	client := NewClient(srv.URL, "wrong-token")
	_, err := client.SendTask(context.Background(), AgentCard{}, Message{Role: "agent", Parts: []Part{{Kind: PartText, Text: "x"}}})
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
}

func TestHandlerExecutorError(t *testing.T) {
	srv := httptest.NewServer(&Handler{Executor: func(ctx context.Context, c AgentCard, m Message) (*Task, error) {
		return nil, errors.New("bot crashed")
	}})
	defer srv.Close()

	client := NewClient(srv.URL, "")
	_, err := client.SendTask(context.Background(), AgentCard{}, Message{Role: "agent", Parts: []Part{{Kind: PartText, Text: "x"}}})
	if err == nil {
		t.Fatal("expected executor error surfaced, got nil")
	}
	if !errors.Is(err, nil) {
		// non-nil wrapped error; assert the message is surfaced.
		if err.Error() == "" {
			t.Fatal("executor error message is empty")
		}
	}
}

func TestHandlerUnknownMethod(t *testing.T) {
	srv := httptest.NewServer(&Handler{Executor: func(ctx context.Context, c AgentCard, m Message) (*Task, error) {
		return &Task{ID: "t", State: TaskStateCompleted}, nil
	}})
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":"1","method":"task/get","params":{}}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error in body)", resp.StatusCode)
	}
}

func TestMessageTextConcatenation(t *testing.T) {
	m := Message{Role: "agent", Parts: []Part{
		{Kind: PartText, Text: "hello "},
		{Kind: PartData, Data: map[string]any{"x": 1}},
		{Kind: PartText, Text: "world"},
	}}
	if got := m.Text(); got != "hello world" {
		t.Fatalf("Text() = %q, want 'hello world'", got)
	}
}
