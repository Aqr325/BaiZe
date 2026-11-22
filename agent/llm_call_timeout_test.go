package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type blockingLLMTransport struct {
	ctx context.Context
}

func (t *blockingLLMTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.ctx = req.Context()
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestQuotaAwareTransportBoundsEachLLMCall: a provider that accepts the request
// and never answers must be cut off by a per-call deadline, even though the
// caller's work context carries no deadline of its own.
func TestQuotaAwareTransportBoundsEachLLMCall(t *testing.T) {
	t.Setenv(LLMCallTimeoutEnv, "1")
	base := &blockingLLMTransport{}
	tr := quotaAwareTransport{base: base}
	req, err := http.NewRequest(http.MethodPost, "http://llm.invalid/v1/chat", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = tr.RoundTrip(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("deadline took too long: %s", d)
	}
}

type contextCapturingTransport struct {
	ctx context.Context
}

func (t *contextCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.ctx = req.Context()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

// TestQuotaAwareTransportReleasesDeadlineOnBodyClose makes sure the per-call
// context is not leaked for the lifetime of a long-lived provider. The deadline
// must survive while the SSE body streams, then be released on Close.
func TestQuotaAwareTransportReleasesDeadlineOnBodyClose(t *testing.T) {
	t.Setenv(LLMCallTimeoutEnv, "3600")
	base := &contextCapturingTransport{}
	tr := quotaAwareTransport{base: base}
	req, err := http.NewRequest(http.MethodPost, "http://llm.invalid/v1/chat", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if base.ctx == nil {
		t.Fatal("transport did not see a request context")
	}
	if base.ctx.Err() != nil {
		t.Fatal("deadline fired before the body was closed")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if base.ctx.Err() == nil {
		t.Fatal("closing the body should release the per-call deadline")
	}
}
