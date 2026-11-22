package agent

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCallBudgetCountsAndCancelsOnce(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var cancelCalls atomic.Int64
	// wrap the real cancel to count invocations
	wrapped := func(cause error) { cancelCalls.Add(1); cancel(cause) }
	b := NewCallBudget(3, wrapped)
	ctx = WithCallBudget(ctx, b)

	if got := CallBudgetFromContext(ctx); got != b {
		t.Fatal("budget not retrievable from context")
	}
	for i := 0; i < 3; i++ {
		if err := b.Spend(); err != nil {
			t.Fatalf("spend %d rejected early: %v", i+1, err)
		}
	}
	if cancelCalls.Load() != 0 {
		t.Fatalf("cancelled before limit: %d", cancelCalls.Load())
	}
	// 4th call exceeds: reject + cancel exactly once
	if err := b.Spend(); !errors.Is(err, AbortCallBudgetExhausted) {
		t.Fatalf("expected exhaustion error, got %v", err)
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("cancel calls = %d, want 1", cancelCalls.Load())
	}
	if !errors.Is(context.Cause(ctx), AbortCallBudgetExhausted) {
		t.Fatalf("context cause = %v, want AbortCallBudgetExhausted", context.Cause(ctx))
	}
	// further spends keep rejecting without re-cancelling
	for i := 0; i < 5; i++ {
		if err := b.Spend(); !errors.Is(err, AbortCallBudgetExhausted) {
			t.Fatalf("post-exhaust spend accepted: %v", err)
		}
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("cancel called again after exhaustion: %d", cancelCalls.Load())
	}
}

func TestCallBudgetDisabledAndNil(t *testing.T) {
	if b := NewCallBudget(0, nil); b != nil {
		t.Fatal("limit 0 should yield nil budget")
	}
	if b := NewCallBudget(-1, nil); b != nil {
		t.Fatal("negative limit should yield nil budget")
	}
	// nil budget always allows; nil *CallBudget.Spend() is safe
	var nilBudget *CallBudget
	for i := 0; i < 1000; i++ {
		if err := nilBudget.Spend(); err != nil {
			t.Fatalf("nil budget rejected: %v", err)
		}
	}
	// WithCallBudget(nil) is a no-op
	ctx := WithCallBudget(context.Background(), nil)
	if CallBudgetFromContext(ctx) != nil {
		t.Fatal("nil budget should not be attached")
	}
}

func TestCallBudgetConcurrentSpend(t *testing.T) {
	const limit = 50
	const goroutines = 8
	var cancels atomic.Int64
	b := NewCallBudget(limit, func(error) { cancels.Add(1) })

	var wg sync.WaitGroup
	var allowed atomic.Int64
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if err := b.Spend(); err == nil {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	// exactly `limit` spends succeed regardless of interleaving
	if got := allowed.Load(); got != limit {
		t.Fatalf("allowed spends = %d, want %d", got, limit)
	}
	if cancels.Load() != 1 {
		t.Fatalf("cancel calls = %d, want 1", cancels.Load())
	}
}

// end-to-end: the budget on the request context is spent by the transport, and
// exhaustion stops the request before it reaches the base round tripper.
func TestRateLimitedTransportEnforcesCallBudget(t *testing.T) {
	var baseCalls atomic.Int64
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		baseCalls.Add(1)
		return &http.Response{StatusCode: 200}, nil
	})
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	b := NewCallBudget(2, cancel)
	tr := rateLimitedTransport{base: base, limiter: &RequestLimiter{}}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(WithCallBudget(ctx, b), http.MethodGet, "http://example.test", nil)
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("request %d blocked early: %v", i, err)
		}
	}
	if baseCalls.Load() != 2 {
		t.Fatalf("base calls = %d, want 2", baseCalls.Load())
	}
	req, _ := http.NewRequestWithContext(WithCallBudget(ctx, b), http.MethodGet, "http://example.test", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, AbortCallBudgetExhausted) {
		t.Fatalf("expected budget error, got %v", err)
	}
	if baseCalls.Load() != 2 {
		t.Fatalf("base called after exhaustion: %d", baseCalls.Load())
	}
	if ctx.Err() == nil {
		t.Fatal("context not cancelled on exhaustion")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
