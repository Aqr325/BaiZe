package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// DefaultIntentCallBudget is the conservative cap on HTTP attempts one intent
// may issue across ALL retry layers (SDK connect/empty retries, the same-provider
// safety-window replay, profile failover and model_error intent reruns). The
// request limiter sits on the HTTP transport, the single choke point every layer
// passes through, so this budget counts real billable calls rather than logical
// requests. A normal intent makes a few dozen calls; a few hundred means the
// provider is failing repeatedly and the multiplicative retry ladder is running
// away. Zero or negative disables the cap (legacy behavior).
const DefaultIntentCallBudget = 200

// CallBudget is a per-intent, concurrency-safe cap on LLM HTTP attempts. It is
// carried on the work context so all retry layers share one counter; spending is
// atomic and the cancel hook fires exactly once when the cap is reached.
type CallBudget struct {
	limit  int64
	spent  atomic.Int64
	once   sync.Once
	cancel context.CancelCauseFunc
}

// NewCallBudget builds a budget with limit attempts. cancel is invoked with
// AbortCallBudgetExhausted the first time the limit is hit; pass nil to only
// count without cancelling (useful for tests). limit <= 0 returns nil (no cap).
func NewCallBudget(limit int, cancel context.CancelCauseFunc) *CallBudget {
	if limit <= 0 {
		return nil
	}
	return &CallBudget{limit: int64(limit), cancel: cancel}
}

type callBudgetKey struct{}

// WithCallBudget attaches a budget to ctx. The budget's cancel hook should be
// the same one that cancels the work context, so exhausting it unwinds every
// retry layer (all of them stop when ctx.Err() != nil).
func WithCallBudget(ctx context.Context, b *CallBudget) context.Context {
	if b == nil {
		return ctx
	}
	return context.WithValue(ctx, callBudgetKey{}, b)
}

// CallBudgetFromContext returns the budget attached to ctx, or nil.
func CallBudgetFromContext(ctx context.Context) *CallBudget {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(callBudgetKey{}).(*CallBudget)
	return b
}

// Spend consumes one attempt. It returns an error (and fires the cancel hook)
// only when the cap is exceeded; a nil budget is always allowed. Once the cap
// is hit, every subsequent call is rejected so runaway retries stop immediately.
func (b *CallBudget) Spend() error {
	if b == nil {
		return nil
	}
	if b.spent.Add(1) <= b.limit {
		return nil
	}
	b.once.Do(func() {
		if b.cancel != nil {
			b.cancel(AbortCallBudgetExhausted)
		}
	})
	return fmt.Errorf("%w: 单意图 LLM 调用已达上限 %d 次（五层重试累计），已熔断以避免计费失控", AbortCallBudgetExhausted, b.limit)
}
