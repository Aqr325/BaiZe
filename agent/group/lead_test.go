package group

import (
	"strings"
	"testing"
)

// ---- lead routing fixtures ----------------------------------------------

func leadRoom() Room {
	r := testRoom()
	r.Routing = "lead"
	r.LeadMemberID = "m-alice" // alice is the lead
	return r
}

func leadCtx() map[string]any {
	return map[string]any{"routing": "lead", "lead_member_id": "m-alice", "purpose": "", "notes": ""}
}

func routedEvent(seq int, discussionID, target, assignedBy string) Event {
	return Event{Seq: seq, EventID: "er" + itoa(seq), Kind: RoomRouted,
		Actor:              Actor{Kind: "member", ID: assignedBy, Profile: assignedBy},
		Payload:            map[string]any{"discussion_event_id": discussionID, "target_member_id": target, "assigned_by": assignedBy},
		AuthorityGatewayID: "gw-1", AuthorityEpoch: 1}
}

// ---- unit: LeadRoutingActive --------------------------------------------

func TestLeadRoutingActive(t *testing.T) {
	room := leadRoom()
	if !LeadRoutingActive(room, "", "") {
		t.Fatal("lead room with lead id should be active")
	}
	if LeadRoutingActive(room, "everyone", room.LeadMemberID) {
		t.Fatal("routing=everyone must be inactive")
	}
	if LeadRoutingActive(room, "lead", "m-missing") {
		t.Fatal("unknown lead id must be inactive")
	}
	if !LeadRoutingActive(testRoom(), "lead", "m-alice") {
		t.Fatal("explicit ctx lead should activate even when the room row lacks it (ctx is authoritative)")
	}
}

// ---- unit: LeadRouteTarget ----------------------------------------------

func TestLeadRouteTarget(t *testing.T) {
	room := testRoom()
	cases := map[string]string{
		"@bob please take this": "m-bob",
		"give it to @carol":     "m-carol",
		"@BOB":                  "m-bob", // case-insensitive
		"@bob then @carol":      "m-bob", // first mention wins
		"@all everyone":         "",      // not a real assignment
		"no mention here":       "",
		"(pass)":                "",
	}
	for text, want := range cases {
		if got := LeadRouteTarget(text, room); got != want {
			t.Errorf("LeadRouteTarget(%q) = %q, want %q", text, got, want)
		}
	}
}

// ---- unit: RoutedTarget --------------------------------------------------

func TestRoutedTarget(t *testing.T) {
	// No routed event yet.
	if target, attempted := RoutedTarget(nil, "e1"); attempted || target != "" {
		t.Fatalf("empty log: got (%q,%v), want (\"\",false)", target, attempted)
	}
	events := []Event{userEvent(1, "t1", "x"), routedEvent(2, "e1", "m-bob", "m-alice")}
	validated := ValidatedEvents(events, testRoom())
	target, attempted := RoutedTarget(validated, "e1")
	if !attempted || target != "m-bob" {
		t.Fatalf("routed: got (%q,%v), want (m-bob,true)", target, attempted)
	}
	// Attempted but empty target (failed lead route) must report attempted=true.
	events2 := []Event{userEvent(1, "t1", "x"), routedEvent(2, "e1", "", "m-alice")}
	target2, attempted2 := RoutedTarget(ValidatedEvents(events2, testRoom()), "e1")
	if !attempted2 || target2 != "" {
		t.Fatalf("failed route: got (%q,%v), want (\"\",true)", target2, attempted2)
	}
	// A routed event for another discussion must not match.
	events3 := []Event{userEvent(1, "t1", "x"), routedEvent(2, "e9", "m-bob", "m-alice")}
	_, attempted3 := RoutedTarget(ValidatedEvents(events3, testRoom()), "e1")
	if attempted3 {
		t.Fatal("routed for another discussion must not match")
	}
}

// ---- integration: PlanNextTask lead flows -------------------------------

func TestPlanNextTaskLeadRouteTurn(t *testing.T) {
	// No routing decision yet and the message names nobody → the lead (alice)
	// gets a routing turn (StatusRoute), not a normal member turn.
	events := []Event{userEvent(1, "t1", "compare these three options")}
	dec, err := PlanNextTask(leadRoom(), events, localProfiles(), DefaultLimits(), leadCtx())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusRoute || dec.Reason != "lead_route" {
		t.Fatalf("status=%s reason=%s, want route/lead_route", dec.Status, dec.Reason)
	}
	if dec.Task == nil || dec.Task.Member.Handle != "alice" {
		t.Fatalf("lead turn member = %v, want alice", dec.Task)
	}
	prompt := dec.Task.Payload["prompt"].(string)
	if !strings.Contains(prompt, "room lead") || !strings.Contains(prompt, "@bob") {
		t.Fatalf("lead prompt missing lead instruction/roster: %q", prompt)
	}
}

func TestPlanNextTaskLeadAssigned(t *testing.T) {
	// Routing done (lead assigned bob) and bob has not spoken → bob answers with
	// AssignedBy=alice in the prompt.
	events := []Event{userEvent(1, "t1", "compare options"), routedEvent(2, "e1", "m-bob", "m-alice")}
	dec, err := PlanNextTask(leadRoom(), events, localProfiles(), DefaultLimits(), leadCtx())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusTask || dec.Reason != "lead_assigned" {
		t.Fatalf("status=%s reason=%s, want task/lead_assigned", dec.Status, dec.Reason)
	}
	if dec.Task == nil || dec.Task.Member.Handle != "bob" {
		t.Fatalf("assigned member = %v, want bob", dec.Task)
	}
	if dec.Task.RoundIndex != 0 {
		t.Fatalf("round=%d, want 0", dec.Task.RoundIndex)
	}
	prompt := dec.Task.Payload["prompt"].(string)
	if !strings.Contains(prompt, "@alice gave the user's message to you") {
		t.Fatalf("prompt missing lead assignment note: %q", prompt)
	}
}

func TestPlanNextTaskLeadNamedBypasses(t *testing.T) {
	// A message that names someone bypasses the lead entirely: @carol resolves
	// directly (no lead routing turn).
	events := []Event{userEvent(1, "t1", "@carol please summarize")}
	dec, err := PlanNextTask(leadRoom(), events, localProfiles(), DefaultLimits(), leadCtx())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusTask || dec.Task == nil || dec.Task.Member.Handle != "carol" {
		t.Fatalf("named message: status=%s member=%v, want task/carol (no lead turn)", dec.Status, dec.Task)
	}
}

func TestPlanNextTaskLeadFallsBackToEveryone(t *testing.T) {
	// The lead attempted a route but yielded nobody (target="") → the discussion
	// falls back to the ordinary round-robin path from round 0.
	events := []Event{userEvent(1, "t1", "compare options"), routedEvent(2, "e1", "", "m-alice")}
	dec, err := PlanNextTask(leadRoom(), events, localProfiles(), DefaultLimits(), leadCtx())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusTask || dec.Task == nil || dec.Task.Member.Handle != "alice" {
		t.Fatalf("fallback: status=%s member=%v, want task/alice (round-robin)", dec.Status, dec.Task)
	}
	if dec.Task.RoundIndex != 0 {
		t.Fatalf("fallback round=%d, want 0", dec.Task.RoundIndex)
	}
}

func TestPlanNextTaskLeadThenMentionFlow(t *testing.T) {
	// Lead assigned bob, bob answered (round 0). Then carol cites @bob in round
	// 1 — the ordinary mention flow pulls bob back in (agent-to-agent @ still
	// works under lead routing).
	events := []Event{
		userEvent(1, "t1", "audit the pipeline"),
		routedEvent(2, "e1", "m-bob", "m-alice"),
		memberEvent(3, "e1", "m-bob", "t1", "bob took the lead's assignment.", 0),
		terminalEvent(4, "e1", "m-bob", 0, "dm3"),
		memberEvent(5, "e1", "m-carol", "t1", "@bob confirm the edge case too.", 1),
		terminalEvent(6, "e1", "m-carol", 1, "dm5"),
	}
	dec, err := PlanNextTask(leadRoom(), events, localProfiles(), DefaultLimits(), leadCtx())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusTask || dec.Task == nil {
		t.Fatalf("status=%s task=%v, want task (bob pulled into round 1)", dec.Status, dec.Task)
	}
	if dec.Task.Member.Handle != "bob" || dec.Task.RoundIndex != 1 {
		t.Fatalf("round-1 responder = %s round=%d, want bob/1", dec.Task.Member.Handle, dec.Task.RoundIndex)
	}
}
