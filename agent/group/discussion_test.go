package group

import (
	"strings"
	"testing"
)

// ---- fixtures ------------------------------------------------------------

func testRoom() Room {
	return Room{
		RoomID:         "room-1",
		Name:           "Research Squad",
		Members: []Member{
			{MemberID: "m-alice", Profile: "alice", Handle: "alice"},
			{MemberID: "m-bob", Profile: "bob", Handle: "bob"},
			{MemberID: "m-carol", Profile: "carol", Handle: "carol"},
		},
		GatewayID:      "gw-1",
		AuthorityEpoch: 1,
	}
}

func localProfiles() []string { return []string{"alice", "bob", "carol"} }

func userEvent(seq int, thread, text string) Event {
	return Event{Seq: seq, EventID: "e" + itoa(seq), Kind: MessageUser,
		Actor: Actor{Kind: "user", ID: "human"},
		Payload: map[string]any{"text": text, "thread_id": thread},
		AuthorityGatewayID: "gw-1", AuthorityEpoch: 1}
}

func memberEvent(seq int, discussionID, memberID, thread, text string, round int) Event {
	return Event{Seq: seq, EventID: "dm" + itoa(seq), Kind: MessageMember,
		Actor: Actor{Kind: "member", ID: memberID, Profile: memberID},
		Payload: map[string]any{
			"text": text, "thread_id": thread, "member_id": memberID,
			"discussion_event_id": discussionID, "round_index": round,
		},
		AuthorityGatewayID: "gw-1", AuthorityEpoch: 1}
}

// terminalEvent settles a member turn; messageEventID must equal the member
// message's event id so the member message is "committed" into the thread log.
func terminalEvent(seq int, discussionID, memberID string, round int, messageEventID string) Event {
	return Event{Seq: seq, EventID: "e" + itoa(seq), Kind: TurnSettled,
		Actor: Actor{Kind: "gateway", ID: "gw-1"},
		Payload: map[string]any{
			"thread_id": "t1", "member_id": memberID,
			"discussion_event_id": discussionID, "round_index": round,
			"message_event_id": messageEventID,
		},
		AuthorityGatewayID: "gw-1", AuthorityEpoch: 1}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// ---- mention resolution --------------------------------------------------

func TestResolveMentions(t *testing.T) {
	room := testRoom()
	// No mention + defaultAll → everyone.
	all := ResolveMentions([]string{"look at this"}, room.Members, true)
	if len(all) != 3 {
		t.Fatalf("no-mention defaultAll: got %d members, want 3", len(all))
	}
	// @bob scopes the round to bob.
	bob := ResolveMentions([]string{"@bob what do you think"}, room.Members, true)
	if len(bob) != 1 || bob[0].Handle != "bob" {
		t.Fatalf("@bob: got %+v, want [bob]", bob)
	}
	// @all → everyone.
	everyone := ResolveMentions([]string{"@all report"}, room.Members, true)
	if len(everyone) != 3 {
		t.Fatalf("@all: got %d members, want 3", len(everyone))
	}
	// No mention + !defaultAll → nobody.
	none := ResolveMentions([]string{"just text"}, room.Members, false)
	if len(none) != 0 {
		t.Fatalf("no-mention !defaultAll: got %d members, want 0", len(none))
	}
	// @everyone → everyone.
	ev := ResolveMentions([]string{"@everyone go"}, room.Members, true)
	if len(ev) != 3 {
		t.Fatalf("@everyone: got %d members, want 3", len(ev))
	}
	// Case-insensitive handle match.
	upper := ResolveMentions([]string{"@BOB hi"}, room.Members, true)
	if len(upper) != 1 || upper[0].Handle != "bob" {
		t.Fatalf("@BOB: got %+v, want [bob]", upper)
	}
}

func TestIsPassText(t *testing.T) {
	cases := map[string]bool{
		"": true, "(pass)": true, "pass": true, "pass.": true,
		"PASS": true, "(pass).": true, "  pass  ": true,
		"hello": false, "passing": false,
	}
	for text, want := range cases {
		if got := IsPassText(text); got != want {
			t.Errorf("IsPassText(%q) = %v, want %v", text, got, want)
		}
	}
}

// ---- plan_next_task ------------------------------------------------------

func TestPlanNextTaskFirstRoundAll(t *testing.T) {
	// A human message with no mention addresses everyone; the first rotated
	// member (round 0 = roster order) gets the turn.
	events := []Event{userEvent(1, "t1", "compare these three options")}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("PlanNextTask err: %v", err)
	}
	if dec.Status != StatusTask || dec.Reason != "member_turn" {
		t.Fatalf("status=%s reason=%s, want task/member_turn", dec.Status, dec.Reason)
	}
	if dec.Task == nil {
		t.Fatal("task is nil")
	}
	if dec.Task.Member.Handle != "alice" {
		t.Fatalf("first responder = %s, want alice", dec.Task.Member.Handle)
	}
	if dec.Task.RoundIndex != 0 || dec.Task.SeenThroughSeq != 1 {
		t.Fatalf("round=%d seen=%d, want 0/1", dec.Task.RoundIndex, dec.Task.SeenThroughSeq)
	}
	if !strings.Contains(dec.Task.Payload["prompt"].(string), "[Discussion:") {
		t.Fatalf("prompt missing [Discussion: header: %q", dec.Task.Payload["prompt"])
	}
}

func TestPlanNextTaskMentionScopes(t *testing.T) {
	// @carol scopes the first round to carol.
	events := []Event{userEvent(1, "t1", "@carol please summarize")}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Task == nil || dec.Task.Member.Handle != "carol" {
		t.Fatalf("responder = %v, want carol", dec.Task)
	}
}

func TestPlanNextTaskSilentRoundSettles(t *testing.T) {
	// Round 0 schedules every member serially. Once all three have spoken and
	// nobody cites a peer, the next round has no responders and no member
	// message: the room settles (silent_round).
	events := []Event{
		userEvent(1, "t1", "decide the approach"),
		memberEvent(2, "e1", "m-alice", "t1", "I propose option B.", 0),
		terminalEvent(3, "e1", "m-alice", 0, "dm2"),
		memberEvent(4, "e1", "m-bob", "t1", "B works for me.", 0),
		terminalEvent(5, "e1", "m-bob", 0, "dm4"),
		memberEvent(6, "e1", "m-carol", "t1", "Agreed.", 0),
		terminalEvent(7, "e1", "m-carol", 0, "dm6"),
	}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusSettled || dec.Reason != "silent_round" {
		t.Fatalf("status=%s reason=%s, want settled/silent_round", dec.Status, dec.Reason)
	}
}

func TestPlanNextTaskBotCitationPullsPeer(t *testing.T) {
	// Round 0 is serial over the whole roster. bob speaks first, then alice
	// cites @bob in her turn, then carol closes round 0. bob's last post
	// (seq 2) precedes alice's citation (seq 4), so round 1 pulls bob back in.
	events := []Event{
		userEvent(1, "t1", "audit the pipeline"),
		memberEvent(2, "e1", "m-bob", "t1", "bob reviewed the first half.", 0),
		terminalEvent(3, "e1", "m-bob", 0, "dm2"),
		memberEvent(4, "e1", "m-alice", "t1", "I checked it, @bob can confirm the edge case.", 0),
		terminalEvent(5, "e1", "m-alice", 0, "dm4"),
		memberEvent(6, "e1", "m-carol", "t1", "carol sees no blocker.", 0),
		terminalEvent(7, "e1", "m-carol", 0, "dm6"),
	}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Status != StatusTask {
		t.Fatalf("status=%s, want task (bob pulled into round 1)", dec.Status)
	}
	if dec.Task.Member.Handle != "bob" {
		t.Fatalf("round-1 responder = %s, want bob", dec.Task.Member.Handle)
	}
	if dec.Task.RoundIndex != 1 {
		t.Fatalf("round = %d, want 1", dec.Task.RoundIndex)
	}
}

func TestPlanNextTaskSkipsTerminalMember(t *testing.T) {
	// Round 0: bob and carol already spoke (terminal). alice has not: the plan
	// must skip the terminals and give the turn to alice.
	events := []Event{
		userEvent(1, "t1", "who reviews next"),
		memberEvent(2, "e1", "m-bob", "t1", "bob said x.", 0),
		terminalEvent(3, "e1", "m-bob", 0, "dm2"),
		memberEvent(4, "e1", "m-carol", "t1", "carol said y.", 0),
		terminalEvent(5, "e1", "m-carol", 0, "dm4"),
	}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Task == nil || dec.Task.Member.Handle != "alice" {
		t.Fatalf("responder = %v, want alice (only non-terminal)", dec.Task)
	}
}

func TestPlanNextTaskWatermarkAdvances(t *testing.T) {
	// After bob speaks (round 1), a fresh user message opens a new discussion
	// where bob's watermark is at his last seen seq — old messages are not
	// replayed to him, but the newest delta is.
	events := []Event{
		userEvent(1, "t1", "start"),
		memberEvent(2, "e1", "m-alice", "t1", "a says hi", 0),
		terminalEvent(3, "e1", "m-alice", 0, "dm2"),
		memberEvent(4, "e1", "m-bob", "t1", "b says hi @carol", 1),
		terminalEvent(5, "e1", "m-bob", 1, "dm4"),
		// new discussion, same thread
		userEvent(6, "t1", "second round"),
	}
	dec, err := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Task == nil || dec.Task.Member.Handle != "alice" {
		t.Fatalf("responder = %v, want alice (first in new discussion)", dec.Task)
	}
	// New discussion started at seq 6; alice's delta begins there.
	if dec.Task.SeenThroughSeq != 6 {
		t.Fatalf("seen = %d, want 6", dec.Task.SeenThroughSeq)
	}
}

// ---- plan_publication ----------------------------------------------------

func TestPlanPublicationSettledPublishesMessage(t *testing.T) {
	events := []Event{userEvent(1, "t1", "hello everyone")}
	dec, _ := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	plan, err := PlanPublication(testRoom(), events, *dec.Task, TermSettled,
		map[string]any{"text": "My answer."}, localProfiles())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if plan.TerminalKind != TermSettled {
		t.Fatalf("terminal = %s, want settled", plan.TerminalKind)
	}
	if len(plan.Events) != 2 {
		t.Fatalf("events = %d, want 2 (message + terminal)", len(plan.Events))
	}
	if plan.Events[0].Kind != MessageMember || plan.Events[0].Payload["text"] != "My answer." {
		t.Fatalf("first event = %s, want message.member with text", plan.Events[0].Kind)
	}
	if plan.Events[1].Kind != TurnSettled {
		t.Fatalf("second event = %s, want turn.settled", plan.Events[1].Kind)
	}
}

func TestPlanPublicationDirectReplyPassFails(t *testing.T) {
	// @bob was directly addressed but returns "(pass)": it becomes a failure.
	events := []Event{userEvent(1, "t1", "@bob decide")}
	dec, _ := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	if dec.Task == nil || dec.Task.Member.Handle != "bob" {
		t.Fatalf("responder = %v, want bob", dec.Task)
	}
	plan, err := PlanPublication(testRoom(), events, *dec.Task, TermSettled,
		map[string]any{"text": "(pass)"}, localProfiles())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if plan.TerminalKind != TermFailed {
		t.Fatalf("terminal = %s, want failed (direct reply passed)", plan.TerminalKind)
	}
	if plan.Events[0].Kind != TurnFailed {
		t.Fatalf("event = %s, want turn.failed", plan.Events[0].Kind)
	}
	errText := plan.Events[0].Payload["error"].(string)
	if !strings.Contains(errText, "@bob was directly addressed") {
		t.Fatalf("error = %q, want direct-address failure", errText)
	}
}

func TestPlanPublicationPassIsSilent(t *testing.T) {
	// A non-addressed member passing publishes only a settled terminal (no message).
	events := []Event{
		userEvent(1, "t1", "open floor"),
		memberEvent(2, "e1", "m-alice", "t1", "a first", 0),
		terminalEvent(3, "e1", "m-alice", 0, "dm2"),
	}
	dec, _ := PlanNextTask(testRoom(), events, localProfiles(), DefaultLimits(), nil)
	plan, err := PlanPublication(testRoom(), events, *dec.Task, TermSettled,
		map[string]any{"text": "(pass)"}, localProfiles())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(plan.Events) != 1 || plan.Events[0].Kind != TurnSettled {
		t.Fatalf("events = %+v, want single turn.settled (silent)", plan.Events)
	}
}

// ---- prompt --------------------------------------------------------------

func TestBuildPromptFormat(t *testing.T) {
	room := testRoom()
	messages := []ValidatedEvent{{
		Seq: 1, EventID: "e1", Kind: MessageUser,
		Payload: map[string]any{"text": "compare the plans", "thread_id": "t1"},
	}}
	prompt, err := BuildPrompt(room, room.Members[0], messages, 0, 1, PromptOpts{ReplyRequired: true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, want := range []string{
		"[Discussion: \"Research Squad\"]",
		"You are @alice",
		"@bob, @carol",
		"New messages in this thread since your last turn (oldest first):",
		"User (user): compare the plans",
		"- The user directly addressed you.",
		"- Mention a teammate by handle to pull them into the next round",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q\n---\n%s", want, prompt)
		}
	}
}

func TestBuildPromptTruncatesOversizedDelta(t *testing.T) {
	room := testRoom()
	messages := []ValidatedEvent{}
	// 40 messages x ~6KB each: the newest 24 exceed the 128KB prompt budget.
	for i := 1; i <= 40; i++ {
		messages = append(messages, ValidatedEvent{Seq: i, EventID: "e" + itoa(i), Kind: MessageUser,
			Payload: map[string]any{"text": strings.Repeat("x", 6000) + " " + itoa(i), "thread_id": "t1"}})
	}
	prompt, err := BuildPrompt(room, room.Members[0], messages, 0, 40, PromptOpts{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(prompt) > MaxPromptBytes {
		t.Fatalf("prompt %d bytes exceeds MaxPromptBytes", len(prompt))
	}
	if !strings.Contains(prompt, "[Earlier content omitted to fit this turn.]") {
		t.Fatalf("oversized delta not marked as omitted")
	}
}

func TestTurnRound(t *testing.T) {
	if r, ok := TurnRound("d3.r2.p1.s9.mabcdef0123456789abcdef01"); !ok || r != 2 {
		t.Fatalf("TurnRound = %d/%v, want 2/true", r, ok)
	}
	if _, ok := TurnRound("not-a-turn"); ok {
		t.Fatalf("TurnRound accepted invalid id")
	}
}
