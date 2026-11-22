package db

import (
	"testing"
	"time"

	"github.com/Autumn-27/baize/agent/delegation"
)

// TestSubagentLedgerRoundTrip exercises the durable subagent ledger end to end
// against the live dev PG: UpsertLaunch -> UpdateState -> UpdateResult -> Get
// -> List, then a terminal-state row is left untouched by RecoverStuck.
func TestSubagentLedgerRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	defer d.Exec(`DELETE FROM subagent_runs WHERE subagent_id = $1`, "test-sub-ledger-1") //nolint:errcheck

	nowSec := float64(time.Now().Unix())
	h := delegation.Handle{
		SubagentID:      "test-sub-ledger-1",
		ParentSessionID: "sess-ledger",
		CorrelationID:   "corr-1",
		CreatedAt:       nowSec,
		Role:            "leaf",
		Depth:           1,
	}
	req := &delegation.LaunchRequest{
		Goal: "inspect endpoint", Context: "ctx", Role: "leaf",
		Model: "m", Provider: "p", ParentTaskID: 42,
		AllowedToolsets: []string{"web_fetch", "bash"},
		Metadata:        map[string]any{"k": "v"},
	}
	if err := d.UpsertLaunch(h, req); err != nil {
		t.Fatalf("UpsertLaunch: %v", err)
	}

	got, err := d.GetSubagent(h.SubagentID)
	if err != nil {
		t.Fatalf("GetSubagent: %v", err)
	}
	if got.State != "PENDING" || got.ParentTaskID != 42 || got.Goal != "inspect endpoint" {
		t.Fatalf("launch row mismatch: %+v", got)
	}
	if len(got.AllowedToolsets) != 2 || got.AllowedToolsets[0] != "web_fetch" {
		t.Fatalf("toolsets not round-tripped: %v", got.AllowedToolsets)
	}
	if got.Metadata["k"] != "v" {
		t.Fatalf("metadata not round-tripped: %v", got.Metadata)
	}

	// Non-terminal transition.
	if err := d.UpdateState(h.SubagentID, delegation.StateRunning, nowSec+1); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	got, _ = d.GetSubagent(h.SubagentID)
	if got.State != "RUNNING" || got.StartedAt == nil {
		t.Fatalf("state not advanced: %+v", got)
	}

	// Terminal result.
	res := delegation.Result{
		Handle: h, TerminalState: delegation.StateSucceeded, Ready: true,
		Summary: "all good", StartedAt: nowSec, CompletedAt: nowSec + 2,
		UsageMetadata: map[string]any{"api_calls": 3}, ResultHash: "deadbeef",
	}
	if err := d.UpdateResult(h.SubagentID, res); err != nil {
		t.Fatalf("UpdateResult: %v", err)
	}
	got, _ = d.GetSubagent(h.SubagentID)
	if got.State != "SUCCEEDED" || got.ResultHash != "deadbeef" || got.Summary != "all good" {
		t.Fatalf("result not persisted: %+v", got)
	}
	if got.UsageMetadata["api_calls"] != 3 {
		t.Fatalf("usage not round-tripped: %v", got.UsageMetadata)
	}

	// List by parent session.
	list, err := d.ListSubagents("sess-ledger", 10)
	if err != nil {
		t.Fatalf("ListSubagents: %v", err)
	}
	if len(list) == 0 || list[0].SubagentID != h.SubagentID {
		t.Fatalf("list missing row: %+v", list)
	}

	// Terminal row is NOT recovered by RecoverStuck.
	n, err := d.RecoverStuckSubagents()
	if err != nil {
		t.Fatalf("RecoverStuck: %v", err)
	}
	got, _ = d.GetSubagent(h.SubagentID)
	if got.State != "SUCCEEDED" {
		t.Fatalf("terminal row must survive recovery, got %s", got.State)
	}
	_ = n
}

// TestSubagentLedgerRecoverStuck inserts a RUNNING row (as if a restart orphaned
// it) and verifies RecoverStuckSubagents flips it to INTERRUPTED.
func TestSubagentLedgerRecoverStuck(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	defer d.Exec(`DELETE FROM subagent_runs WHERE subagent_id = $1`, "test-sub-ledger-2") //nolint:errcheck

	nowSec := float64(time.Now().Unix())
	h := delegation.Handle{SubagentID: "test-sub-ledger-2", ParentSessionID: "sess-stuck", CreatedAt: nowSec, Role: "leaf", Depth: 1}
	if err := d.UpsertLaunch(h, &delegation.LaunchRequest{Goal: "g"}); err != nil {
		t.Fatalf("UpsertLaunch: %v", err)
	}
	if err := d.UpdateState(h.SubagentID, delegation.StateRunning, nowSec+1); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	n, err := d.RecoverStuckSubagents()
	if err != nil {
		t.Fatalf("RecoverStuck: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected to recover >= 1 orphaned row, got %d", n)
	}
	got, _ := d.GetSubagent(h.SubagentID)
	if got.State != "INTERRUPTED" || got.ErrorClassification != "INTERRUPTED" {
		t.Fatalf("orphaned row not recovered: %+v", got)
	}
	if got.CompletedAt == nil {
		t.Fatalf("recovered row must carry completed_at")
	}
}
