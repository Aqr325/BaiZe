package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/baize/agent/group"
	"github.com/Autumn-27/baize/db"
)

func iptr(n int64) *int64 { return &n }

func dbGroupRoomFixture() *db.GroupRoom {
	return &db.GroupRoom{
		Room: group.Room{RoomID: "g-1", Name: "Squad", GatewayID: "local", AuthorityEpoch: 1,
			Members: []group.Member{
				{MemberID: "m1", Profile: "alice", Handle: "alice"},
				{MemberID: "m2", Profile: "bob", Handle: "bob"},
				{MemberID: "m3", Profile: "carol", Handle: "carol"},
			}},
		Members: []db.GroupMember{
			{Member: group.Member{MemberID: "m1", Profile: "alice", Handle: "alice"}, LLMProfileID: iptr(7), Position: 0},
			{Member: group.Member{MemberID: "m2", Profile: "bob", Handle: "bob"}, Position: 1},
			{Member: group.Member{MemberID: "m3", Profile: "carol", Handle: "carol"}, LLMProfileID: iptr(9), Position: 2},
		},
	}
}

// newGroupTestServer returns a Server without a DB (handlers must 503 cleanly).
func newGroupTestServer() *Server {
	s := &Server{m: &Manager{}, groupLimits: group.DefaultLimits()}
	return s
}

func TestGroupHandlersNoDB(t *testing.T) {
	s := newGroupTestServer()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		handle func(http.ResponseWriter, *http.Request)
	}{
		{"list", http.MethodGet, "/api/groups", "", s.groupList},
		{"create", http.MethodPost, "/api/groups", `{"name":"x","members":[]}`, s.groupCreate},
		{"get", http.MethodGet, "/api/groups/g-1", "", s.groupGet},
		{"send", http.MethodPost, "/api/groups/g-1/messages", `{"text":"hi"}`, s.groupSendMessage},
		{"stop", http.MethodPost, "/api/groups/g-1/stop", "", s.groupStop},
		{"continue", http.MethodPost, "/api/groups/g-1/continue", "", s.groupContinue},
		{"disband", http.MethodPost, "/api/groups/g-1/disband", "", s.groupDisband},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewBufferString(c.body))
			rec := httptest.NewRecorder()
			c.handle(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s: code = %d, want 503", c.name, rec.Code)
			}
		})
	}
}

func TestGroupProfilesHelper(t *testing.T) {
	s := newGroupTestServer()
	room := dbGroupRoomFixture()
	profiles := s.groupProfiles(room)
	if len(profiles) != 3 || profiles[0] != "alice" {
		t.Fatalf("profiles = %v, want [alice bob carol]", profiles)
	}
	if id := s.groupMemberLLMProfile(room, "m1"); id != 7 {
		t.Fatalf("llm profile = %d, want 7", id)
	}
	if id := s.groupMemberLLMProfile(room, "m-none"); id != 0 {
		t.Fatalf("unknown member llm = %d, want 0", id)
	}
}

func TestGroupJSONDecode(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/groups", bytes.NewBufferString(`{"name":"Squad","members":[{"profile":"a","handle":"@alice"}]}`))
	var in groupCreateInput
	if err := decodeJSON(req, &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in.Name != "Squad" || len(in.Members) != 1 || in.Members[0].Handle != "@alice" {
		t.Fatalf("decode mismatch: %+v", in)
	}
	if _, err := json.Marshal(in); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
