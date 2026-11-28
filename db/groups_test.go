package db

import (
	"strings"
	"testing"

	"github.com/Autumn-27/baize/agent/group"
)

// TestGroupRoomRoundTrip exercises the hosted-room store end to end against the
// live dev PG: create -> get (members round-trip) -> append events (seq
// monotonic) -> update -> add/remove member -> disband.
func TestGroupRoomRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	defer d.Exec(`DELETE FROM group_events WHERE room_id='test-room-1'`)  //nolint:errcheck
	defer d.Exec(`DELETE FROM group_members WHERE room_id='test-room-1'`) //nolint:errcheck
	defer d.Exec(`DELETE FROM group_rooms WHERE room_id='test-room-1'`)   //nolint:errcheck

	room := group.Room{
		RoomID: "test-room-1", Name: "Test Squad", GatewayID: "gw-test", AuthorityEpoch: 1,
		Members: []group.Member{
			{MemberID: "m1", Profile: "alice", Handle: "alice"},
			{MemberID: "m2", Profile: "bob", Handle: "bob"},
			{MemberID: "m3", Profile: "carol", Handle: "carol"},
		},
	}
	if err := d.CreateGroupRoom(room, "", map[string]int64{"m1": 7, "m3": 9}, nil); err != nil {
		t.Fatalf("CreateGroupRoom: %v", err)
	}

	got, err := d.GetGroupRoom(room.RoomID)
	if err != nil {
		t.Fatalf("GetGroupRoom: %v", err)
	}
	if got.Room.Name != "Test Squad" || got.MemberCount != 3 {
		t.Fatalf("room mismatch: name=%s count=%d", got.Room.Name, got.MemberCount)
	}
	if got.Members[0].Handle != "alice" || got.Members[2].Handle != "carol" {
		t.Fatalf("member order/roster mismatch: %+v", got.Members)
	}
	if got.Members[0].LLMProfileID == nil || *got.Members[0].LLMProfileID != 7 {
		t.Fatalf("llm binding not round-tripped: %v", got.Members[0].LLMProfileID)
	}
	if got.Members[0].Target == nil || got.Members[0].Target.Kind != "local" {
		t.Fatalf("local target not reconstructed: %+v", got.Members[0].Target)
	}

	// Events: seq must be monotonic and unique per room.
	ev1 := group.Event{EventID: "ev-1", Kind: group.MessageUser, Actor: group.Actor{Kind: "user", ID: "human"},
		Payload:            map[string]any{"text": "hello room", "thread_id": "t1"},
		AuthorityGatewayID: "gw-test", AuthorityEpoch: 1}
	seq1, err := d.AppendGroupEvent(room.RoomID, ev1)
	if err != nil {
		t.Fatalf("AppendGroupEvent ev1: %v", err)
	}
	ev2 := group.Event{EventID: "ev-2", Kind: group.MessageMember, Actor: group.Actor{Kind: "member", ID: "m1", Profile: "alice"},
		Payload:            map[string]any{"text": "@bob check this", "thread_id": "t1", "member_id": "m1", "round_index": 0},
		AuthorityGatewayID: "gw-test", AuthorityEpoch: 1}
	seq2, err := d.AppendGroupEvent(room.RoomID, ev2)
	if err != nil {
		t.Fatalf("AppendGroupEvent ev2: %v", err)
	}
	if seq1 != 1 || seq2 != 2 {
		t.Fatalf("seqs = %d/%d, want 1/2", seq1, seq2)
	}
	latest, err := d.LatestGroupSeq(room.RoomID)
	if err != nil || latest != 2 {
		t.Fatalf("LatestGroupSeq = %d/%v, want 2", latest, err)
	}

	events, err := d.ListGroupEvents(room.RoomID)
	if err != nil {
		t.Fatalf("ListGroupEvents: %v", err)
	}
	if len(events) != 2 || events[0].EventID != "ev-1" || events[0].Text() != "hello room" {
		t.Fatalf("events mismatch: %+v", events)
	}
	if events[1].Actor.Kind != "member" || events[1].Actor.ID != "m1" {
		t.Fatalf("actor not round-tripped: %+v", events[1].Actor)
	}

	// Update + member add/remove.
	if err := d.UpdateGroupRoom(room.RoomID, "Renamed Squad", "purpose", "notes", "everyone", ""); err != nil {
		t.Fatalf("UpdateGroupRoom: %v", err)
	}
	got, _ = d.GetGroupRoom(room.RoomID)
	if got.Room.Name != "Renamed Squad" || got.Room.Purpose != "purpose" {
		t.Fatalf("update not persisted: %+v", got.Room)
	}
	if err := d.AddGroupMember(room.RoomID, group.Member{MemberID: "m4", Profile: "dave", Handle: "dave"}, nil, ""); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	got, _ = d.GetGroupRoom(room.RoomID)
	if got.MemberCount != 4 || got.Members[3].Handle != "dave" {
		t.Fatalf("member add failed: count=%d", got.MemberCount)
	}
	if err := d.RemoveGroupMember(room.RoomID, "m4"); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	got, _ = d.GetGroupRoom(room.RoomID)
	if got.MemberCount != 3 {
		t.Fatalf("member remove failed: count=%d", got.MemberCount)
	}

	// Disband marks the room; GetGroupRoom still returns it (audit keeps log).
	if err := d.DisbandGroupRoom(room.RoomID); err != nil {
		t.Fatalf("DisbandGroupRoom: %v", err)
	}
	got, _ = d.GetGroupRoom(room.RoomID)
	if got.DisbandedAt == nil {
		t.Fatalf("disband not persisted")
	}

	// List sees the room.
	rooms, err := d.ListGroupRooms()
	if err != nil {
		t.Fatalf("ListGroupRooms: %v", err)
	}
	found := false
	for _, r := range rooms {
		if r.Room.RoomID == room.RoomID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("room not listed")
	}
}

// TestGroupEventsSeqUniqueUnderConcurrency appends concurrently and asserts no
// seq collision (the COALESCE(MAX(seq),0)+1 allocation is serialized by PG).
func TestGroupEventsSeqUniqueUnderConcurrency(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	defer d.Exec(`DELETE FROM group_events WHERE room_id='test-room-2'`)  //nolint:errcheck
	defer d.Exec(`DELETE FROM group_members WHERE room_id='test-room-2'`) //nolint:errcheck
	defer d.Exec(`DELETE FROM group_rooms WHERE room_id='test-room-2'`)   //nolint:errcheck

	room := group.Room{RoomID: "test-room-2", Name: "R2", GatewayID: "gw", AuthorityEpoch: 1,
		Members: []group.Member{
			{MemberID: "m1", Profile: "alice", Handle: "alice"},
			{MemberID: "m2", Profile: "bob", Handle: "bob"},
		}}
	if err := d.CreateGroupRoom(room, "", nil, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	done := make(chan int, 6)
	for i := 0; i < 6; i++ {
		go func(n int) {
			ev := group.Event{EventID: "evc-" + strings.Repeat("x", 1) + itoaTest(n), Kind: group.MessageUser,
				Actor:              group.Actor{Kind: "user", ID: "human"},
				Payload:            map[string]any{"text": "msg " + itoaTest(n), "thread_id": "t1"},
				AuthorityGatewayID: "gw", AuthorityEpoch: 1}
			seq, _ := d.AppendGroupEvent(room.RoomID, ev)
			done <- seq
		}(i)
	}
	seen := map[int]bool{}
	for i := 0; i < 6; i++ {
		seq := <-done
		if seen[seq] {
			t.Fatalf("seq collision: %d", seq)
		}
		seen[seq] = true
	}
	if len(seen) != 6 {
		t.Fatalf("expected 6 unique seqs, got %d", len(seen))
	}
}

func itoaTest(n int) string {
	return string(rune('0' + n))
}
