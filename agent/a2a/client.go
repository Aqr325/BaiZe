package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client sends A2A requests to a peer gateway's JSON-RPC endpoint.
type Client struct {
	Endpoint string // base URL of the peer A2A endpoint (e.g. https://peer/a2a)
	Token    string // Bearer token ("" = no auth)
	HTTP     *http.Client
}

// NewClient builds a client with a sane default HTTP transport.
func NewClient(endpoint, token string) *Client {
	return &Client{
		Endpoint: endpoint,
		Token:    token,
		HTTP:     &http.Client{Timeout: 120 * time.Second},
	}
}

// SendTask sends a task/send request and returns the peer's resulting Task.
func (c *Client) SendTask(ctx context.Context, card AgentCard, msg Message) (*Task, error) {
	if c.Endpoint == "" {
		return nil, fmt.Errorf("a2a: empty endpoint")
	}
	params, err := json.Marshal(sendParams{Card: card, Message: msg})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request{JSONRPC: "2.0", ID: "baize", Method: MethodSendTask, Params: raw(params)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("a2a: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a2a: status %d: %s", resp.StatusCode, truncate(data, 200))
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("a2a: decode: %w", err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("a2a: error %d: %s", r.Error.Code, r.Error.Message)
	}
	taskJSON, err := json.Marshal(r.Result)
	if err != nil {
		return nil, fmt.Errorf("a2a: result marshal: %w", err)
	}
	var t Task
	if err := json.Unmarshal(taskJSON, &t); err != nil {
		return nil, fmt.Errorf("a2a: result decode: %w", err)
	}
	return &t, nil
}

func raw(b []byte) *json.RawMessage {
	r := json.RawMessage(b)
	return &r
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
