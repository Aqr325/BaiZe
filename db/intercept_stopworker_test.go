package db

import (
	"testing"
)

// TestInterceptRuleStopWorkerRoundTrip verifies stop_worker persists through
// create/list/update (deny 熔断 §3). Skips without a configured PG (matches the
// rest of the db suite).
func TestInterceptRuleStopWorkerRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// cleanup runs LIFO: close registered FIRST (runs LAST), delete SECOND (runs
	// FIRST, while the DB is still open). createdID is captured by reference.
	var createdID int64
	t.Cleanup(func() { _ = d.Close() })
	t.Cleanup(func() {
		if createdID != 0 {
			_ = d.DeleteInterceptRule(createdID)
		}
	})

	// Create with stop_worker on (a counter-measure deny rule).
	created, err := d.CreateInterceptRule(
		"test-stop-worker", "tool_input", "string", "stop-worker-probe",
		"deny", "deny 熔断测试", 1, true, false, 0, "deny", true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	createdID = created.ID

	if !created.StopWorker {
		t.Fatalf("create: StopWorker=%v, want true", created.StopWorker)
	}

	// List reflects it.
	listed, err := d.ListInterceptRules()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, r := range listed {
		if r.ID == created.ID {
			found = true
			if !r.StopWorker {
				t.Fatalf("list: StopWorker=%v, want true", r.StopWorker)
			}
		}
	}
	if !found {
		t.Fatal("created rule not found in list")
	}

	// Update to off.
	updated, err := d.UpdateInterceptRule(
		created.ID, created.Name, created.MatchTarget, created.MatchType, created.Pattern,
		created.Action, created.Message, created.Priority, created.Enabled,
		created.TimeoutEnabled, created.TimeoutSeconds, created.TimeoutAction, false)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.StopWorker {
		t.Fatalf("update: StopWorker=%v, want false", updated.StopWorker)
	}
}
