package delegation

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakePersistence records the Persistence calls the lifecycle makes, so the
// test can assert the durable-ledger wiring without a real DB.
type fakePersistence struct {
	mu      sync.Mutex
	upserts []LaunchRequest
	states  []State
	results []Result
}

func (f *fakePersistence) UpsertLaunch(h Handle, req *LaunchRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts = append(f.upserts, *req)
	return nil
}

func (f *fakePersistence) UpdateState(subagentID string, st State, ts float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states = append(f.states, st)
	return nil
}

func (f *fakePersistence) UpdateResult(subagentID string, r Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, r)
	return nil
}

func (f *fakePersistence) snapshot() (upserts int, states []State, results int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.upserts), append([]State(nil), f.states...), len(f.results)
}

func TestLifecyclePersistenceRoundTrip(t *testing.T) {
	p := &fakePersistence{}
	svc := NewLifecycleService(fakeRunner(), NewBroker(), nil)
	svc.SetPersistence(p)

	h, err := svc.Launch(context.Background(), &LaunchRequest{
		Goal: "inspect the endpoint", Role: "leaf",
		Model: "m", Provider: "prov", ParentSessionID: "sess-9",
	})
	if err != nil {
		t.Fatalf("Launch err: %v", err)
	}
	ts := svc.Wait(h, 5*time.Second)
	if ts.State != StateSucceeded {
		t.Fatalf("state = %s, want succeeded", ts.State)
	}

	upserts, states, results := p.snapshot()
	if upserts != 1 {
		t.Fatalf("upserts = %d, want 1 (one row per launch)", upserts)
	}
	// STARTING then RUNNING are the two non-terminal transitions the lifecycle
	// publishes through setState.
	want := map[State]bool{StateStarting: true, StateRunning: true}
	seen := map[State]bool{}
	for _, st := range states {
		seen[st] = true
	}
	for st := range want {
		if !seen[st] {
			t.Fatalf("missing persisted state %s (saw %v)", st, states)
		}
	}
	if results != 1 {
		t.Fatalf("results = %d, want 1 (one terminal result)", results)
	}
	// The persisted result must be the final record, carrying the hash.
	if !p.results[0].Ready || p.results[0].ResultHash == "" {
		t.Fatalf("persisted result not ready/hashed: %+v", p.results[0])
	}
}

func TestLifecyclePersistenceNoPersistenceByDefault(t *testing.T) {
	// Without SetPersistence the lifecycle runs in-memory only.
	svc := NewLifecycleService(fakeRunner(), NewBroker(), nil)
	h, err := svc.Launch(context.Background(), &LaunchRequest{Goal: "g"})
	if err != nil {
		t.Fatalf("Launch err: %v", err)
	}
	ts := svc.Wait(h, 5*time.Second)
	if ts.State != StateSucceeded {
		t.Fatalf("state = %s, want succeeded", ts.State)
	}
}

func TestLifecycleCancelByID(t *testing.T) {
	runner := func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		<-ctx.Done() // blocks until cancelled
		return ChildOutcome{}, ctx.Err()
	}
	svc := NewLifecycleService(runner, NewBroker(), nil)
	h, err := svc.Launch(context.Background(), &LaunchRequest{Goal: "g"})
	if err != nil {
		t.Fatalf("Launch err: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Unknown id reports UnknownHandle.
	if cr := svc.CancelByID("nope", "stop"); !cr.UnknownHandle {
		t.Fatalf("unknown id must report UnknownHandle, got %+v", cr)
	}
	// Known id cancels without a capability-verified handle.
	cr := svc.CancelByID(h.SubagentID, "stop")
	if !cr.Accepted {
		t.Fatalf("CancelByID not accepted: %+v", cr)
	}
	ts := svc.Wait(h, 3*time.Second)
	if ts.State != StateCancelled {
		t.Fatalf("after CancelByID state = %s, want cancelled", ts.State)
	}
}
