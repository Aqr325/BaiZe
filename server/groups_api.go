package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/baize/agent"
	"github.com/Autumn-27/baize/agent/group"
	"github.com/Autumn-27/baize/db"
)

// newGroupID returns a random 16-byte hex id for a room/event/member.
func newGroupID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("x%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ---- DTOs ----------------------------------------------------------------

type groupMemberInput struct {
	Profile      string `json:"profile"`
	Handle       string `json:"handle"`
	DisplayName  string `json:"display_name"`
	LLMProfileID int64  `json:"llm_profile_id"`
	AgentKey     string `json:"agent_key"` // 可选:绑定现有 agent,成员 turn 用其 system prompt
}

type groupCreateInput struct {
	Name    string             `json:"name"`
	Image   string             `json:"image"`
	Members []groupMemberInput `json:"members"`
}

// ---- room lifecycle ------------------------------------------------------

// groupProfiles returns the roster profiles (all local on a single gateway).
func (s *Server) groupProfiles(room *db.GroupRoom) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range room.Members {
		if !seen[m.Profile] {
			seen[m.Profile] = true
			out = append(out, m.Profile)
		}
	}
	return out
}

// groupMemberLLMProfile returns a member's bound LLM profile id (0 = unbound).
func (s *Server) groupMemberLLMProfile(room *db.GroupRoom, memberID string) int64 {
	for _, m := range room.Members {
		if m.MemberID == memberID && m.LLMProfileID != nil {
			return *m.LLMProfileID
		}
	}
	return 0
}

func (s *Server) groupRoomCtx(room *db.GroupRoom) map[string]any {
	return map[string]any{
		"purpose":        room.Room.Purpose,
		"notes":          room.Room.Notes,
		"routing":        room.Room.Routing,
		"lead_member_id": room.Room.LeadMemberID,
	}
}

func (s *Server) appendGroupEvent(roomID string, ev group.Event) {
	if s.m.pg == nil {
		return
	}
	if _, err := s.m.pg.AppendGroupEvent(roomID, ev); err != nil {
		log.Printf("[group %s] append %s failed: %v", roomID, ev.Kind, err)
	}
}

func roomActivityEvent(dec group.Decision, roomID string) group.Event {
	return group.Event{
		EventID: fmt.Sprintf("dactivity:%d:%s", dec.SourceEventSeq, dec.Reason),
		Kind:    group.RoomActivity,
		Actor:   group.Actor{Kind: "gateway", ID: roomID},
		Payload: map[string]any{
			"status": dec.Status, "reason_code": dec.Reason,
			"thread_id": dec.ThreadID, "discussion_event_id": dec.DiscussionEventID,
		},
		AuthorityGatewayID: roomID, AuthorityEpoch: 1,
	}
}

// ---- handlers ------------------------------------------------------------

// groupCreate builds a 2-6 member room and persists it.
func (s *Server) groupCreate(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var in groupCreateInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, 400, "invalid payload: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeErr(w, 400, "room name is required")
		return
	}
	if len(in.Members) < group.MinMembers || len(in.Members) > group.MaxMembers {
		writeErr(w, 400, fmt.Sprintf("a room needs %d-%d members", group.MinMembers, group.MaxMembers))
		return
	}
	roomID := "g-" + newGroupID()
	room := group.Room{
		RoomID: roomID, Name: strings.TrimSpace(in.Name),
		GatewayID: "local", AuthorityEpoch: 1,
	}
	llmByMember := map[string]int64{}
	agentByMember := map[string]string{}
	for _, mi := range in.Members {
		if strings.TrimSpace(mi.Profile) == "" || strings.TrimSpace(mi.Handle) == "" {
			writeErr(w, 400, "every member needs a profile and handle")
			return
		}
		profile := strings.TrimSpace(mi.Profile)
		handle := strings.TrimPrefix(strings.TrimSpace(mi.Handle), "@")
		room.Members = append(room.Members, group.Member{
			MemberID: "gm-" + newGroupID(), Profile: profile, Handle: handle,
			DisplayName: mi.DisplayName, Target: group.LocalTarget(profile),
		})
		memberID := room.Members[len(room.Members)-1].MemberID
		if mi.LLMProfileID > 0 {
			llmByMember[memberID] = mi.LLMProfileID
		}
		if k := strings.TrimSpace(mi.AgentKey); k != "" {
			if !reAgentKey.MatchString(k) {
				writeErr(w, 400, "agent_key 需小写字母开头，仅含小写字母/数字/下划线")
				return
			}
			if ag, _ := s.m.pg.GetAgentByKey(k); ag == nil {
				writeErr(w, 400, "agent "+k+" 不存在")
				return
			}
			agentByMember[memberID] = k
		}
	}
	if err := s.m.pg.CreateGroupRoom(room, in.Image, llmByMember, agentByMember); err != nil {
		writeErr(w, 500, "failed to create room: "+err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"room_id": roomID})
}

// groupList returns active rooms with member counts and latest-message preview.
func (s *Server) groupList(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	rooms, err := s.m.pg.ListGroupRooms()
	if err != nil {
		writeErr(w, 500, "failed to list rooms: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": rooms})
}

// groupGet returns one room with its full member roster and event log.
func (s *Server) groupGet(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	room, err := s.m.pg.GetGroupRoom(id)
	if err != nil {
		if errors.Is(err, db.ErrGroupNotFound) {
			writeErr(w, 404, "room not found")
			return
		}
		writeErr(w, 500, "failed to get room: "+err.Error())
		return
	}
	events, err := s.m.pg.ListGroupEvents(id)
	if err != nil {
		writeErr(w, 500, "failed to load room log: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"room": room, "events": events})
}

// groupSendMessage appends a user message and starts the discussion turn loop.
func (s *Server) groupSendMessage(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	room, err := s.m.pg.GetGroupRoom(id)
	if err != nil {
		if errors.Is(err, db.ErrGroupNotFound) {
			writeErr(w, 404, "room not found")
			return
		}
		writeErr(w, 500, "failed to get room: "+err.Error())
		return
	}
	if room.DisbandedAt != nil {
		writeErr(w, 409, "room is disbanded")
		return
	}
	var in struct {
		Text     string `json:"text"`
		ThreadID string `json:"thread_id"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, 400, "invalid payload: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Text) == "" {
		writeErr(w, 400, "message text is required")
		return
	}
	threadID := in.ThreadID
	if threadID == "" {
		threadID = "main"
	}
	ev := group.Event{
		EventID: "duser:" + newGroupID(), Kind: group.MessageUser,
		Actor:  group.Actor{Kind: "user", ID: "human"},
		Payload: map[string]any{"text": strings.TrimSpace(in.Text), "thread_id": threadID},
		AuthorityGatewayID: "local", AuthorityEpoch: 1,
	}
	if _, err := s.m.pg.AppendGroupEvent(id, ev); err != nil {
		writeErr(w, 500, "failed to append message: "+err.Error())
		return
	}
	s.startGroupTurn(id)
	writeJSON(w, 202, map[string]any{"status": "accepted", "discussion_event_id": ev.EventID})
}

// groupStop appends a room.stop_requested and cancels the running turn loop.
func (s *Server) groupStop(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	ev := group.Event{
		EventID: "dstop:" + newGroupID(), Kind: group.RoomStopRequest,
		Actor: group.Actor{Kind: "user", ID: "human"},
		Payload: map[string]any{"cancel_id": newGroupID()},
		AuthorityGatewayID: "local", AuthorityEpoch: 1,
	}
	if _, err := s.m.pg.AppendGroupEvent(id, ev); err != nil {
		writeErr(w, 500, "failed to stop room: "+err.Error())
		return
	}
	s.cancelGroupTurn(id)
	writeJSON(w, 200, map[string]any{"status": "stopped"})
}

// groupContinue grants the current discussion another full budget and restarts
// the turn loop (hermes: each Continue adds one budget of rounds and messages).
func (s *Server) groupContinue(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	ev := group.Event{
		EventID: "dcont:" + newGroupID(), Kind: group.RoomContinued,
		Actor: group.Actor{Kind: "user", ID: "human"},
		Payload: map[string]any{"discussion_event_id": r.URL.Query().Get("discussion"), "seen_through_seq": 0},
		AuthorityGatewayID: "local", AuthorityEpoch: 1,
	}
	if _, err := s.m.pg.AppendGroupEvent(id, ev); err != nil {
		writeErr(w, 500, "failed to continue room: "+err.Error())
		return
	}
	s.startGroupTurn(id)
	writeJSON(w, 200, map[string]any{"status": "continued"})
}

// groupDisband marks a room disbanded and cancels its turn loop.
func (s *Server) groupDisband(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := r.PathValue("id")
	if err := s.m.pg.DisbandGroupRoom(id); err != nil {
		writeErr(w, 500, "failed to disband room: "+err.Error())
		return
	}
	s.cancelGroupTurn(id)
	writeJSON(w, 200, map[string]any{"status": "disbanded"})
}

// ---- turn loop -----------------------------------------------------------

// startGroupTurn launches one turn loop per room (idempotent: a running loop is
// left alone, so a new message queues behind the in-flight discussion).
func (s *Server) startGroupTurn(roomID string) {
	s.groupMu.Lock()
	if s.groupRunning == nil {
		s.groupRunning = map[string]context.CancelFunc{}
	}
	if _, ok := s.groupRunning[roomID]; ok {
		s.groupMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.groupRunning[roomID] = cancel
	s.groupMu.Unlock()
	go s.runGroupTurnLoop(ctx, roomID)
}

func (s *Server) cancelGroupTurn(roomID string) {
	s.groupMu.Lock()
	cancel := s.groupRunning[roomID]
	s.groupMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// runGroupTurnLoop is the discussion driver: replay policy, run the planned
// member turn, publish its terminal effects, then re-plan until idle/settled/
// bounded. Mirrors hermes' hosted_room_driver loop.
func (s *Server) runGroupTurnLoop(ctx context.Context, roomID string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[group %s] turn loop panic: %v", roomID, r)
		}
		s.groupMu.Lock()
		delete(s.groupRunning, roomID)
		s.groupMu.Unlock()
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		room, err := s.m.pg.GetGroupRoom(roomID)
		if err != nil || room.DisbandedAt != nil {
			return
		}
		events, err := s.m.pg.ListGroupEvents(roomID)
		if err != nil {
			log.Printf("[group %s] load events: %v", roomID, err)
			return
		}
		profiles := s.groupProfiles(room)
		dec, err := group.PlanNextTask(room.Room, events, profiles, s.groupLimits, s.groupRoomCtx(room))
		if err != nil {
			s.appendGroupEvent(roomID, group.Event{EventID: "dactivity:" + newGroupID(),
				Kind: group.RoomActivity, Actor: group.Actor{Kind: "gateway", ID: roomID},
				Payload: map[string]any{"status": "failed", "reason_code": err.Error(),
					"thread_id": "", "discussion_event_id": ""},
				AuthorityGatewayID: roomID, AuthorityEpoch: 1})
			return
		}
		switch dec.Status {
		case group.StatusIdle:
			return
		case group.StatusSettled, group.StatusBounded:
			s.appendGroupEvent(roomID, roomActivityEvent(dec, roomID))
			return
		case group.StatusTask:
			result, status := s.runGroupMemberTurn(ctx, room, dec.Task)
			plan, err := group.PlanPublication(room.Room, events, *dec.Task, status, result, profiles)
			if err != nil {
				log.Printf("[group %s] publication %s: %v", roomID, status, err)
				return
			}
			for _, ev := range plan.Events {
				s.appendGroupEvent(roomID, group.Event{
					EventID: ev.EventID, Kind: ev.Kind, Actor: ev.Actor, Payload: ev.Payload,
					AuthorityGatewayID: ev.AuthorityGatewayID, AuthorityEpoch: ev.AuthorityEpoch,
				})
			}
		}
	}
}

// resumeGroupDiscussions restarts turn loops for rooms whose discussion is
// incomplete after a process restart. This is the group analog of the task
// runtime restore (restoreTaskRuntimes) and mirrors AET's checkpoint resume:
// the policy planner replays the persisted log and, if a discussion is still
// open (StatusTask), the loop resumes from where it left off. Rooms the user
// manually stopped are skipped, because PlanNextTask treats a stop_requested
// as closing that discussion — so an explicit user stop is never overridden.
func (s *Server) resumeGroupDiscussions() {
	if s.m.pg == nil {
		return
	}
	rooms, err := s.m.pg.ListGroupRooms()
	if err != nil {
		log.Printf("[group] resume scan: %v", err)
		return
	}
	for _, room := range rooms {
		if room.DisbandedAt != nil {
			continue
		}
		events, err := s.m.pg.ListGroupEvents(room.Room.RoomID)
		if err != nil {
			log.Printf("[group %s] resume load events: %v", room.Room.RoomID, err)
			continue
		}
		profiles := s.groupProfiles(&room)
		dec, err := group.PlanNextTask(room.Room, events, profiles, s.groupLimits, s.groupRoomCtx(&room))
		if err != nil {
			log.Printf("[group %s] resume plan: %v", room.Room.RoomID, err)
			continue
		}
		if dec.Status == group.StatusTask {
			log.Printf("[group %s] resume discussion (source_seq=%d)", room.Room.RoomID, dec.SourceEventSeq)
			s.startGroupTurn(room.Room.RoomID)
		}
	}
}

// runGroupMemberTurn runs one Bot's reply to the room prompt. The member's LLM
// profile drives the model; a bound agent key supplies the system prompt (and,
// when the member has no explicit LLM binding, the agent-level model). Unbound
// members fall back to the default assistant agent.
func (s *Server) runGroupMemberTurn(ctx context.Context, room *db.GroupRoom, task *group.TaskPlan) (map[string]any, string) {
	member := task.Member
	agentKey := groupMemberAgentKey(room, member.MemberID)
	if agentKey == "" {
		agentKey = "default"
	}
	profileID := s.groupMemberLLMProfile(room, member.MemberID)
	if profileID <= 0 {
		if pid := s.agentProfileByKey(agentKey); pid > 0 {
			profileID = pid
		}
	}
	var ca *agent.ChatAgent
	if profileID > 0 {
		ca = s.chatAgentForProfile(profileID)
	}
	if ca == nil {
		ca = s.chatAgentRef()
	}
	if ca == nil {
		return map[string]any{"error": "LLM 未就绪，成员无法发言"}, group.TermFailed
	}
	prompt, _ := task.Payload["prompt"].(string)
	sessionID := fmt.Sprintf("group-%s-%s", room.Room.RoomID, member.MemberID)
	maxTurns := s.agentMaxTurns(agentKey)
	maxDuration := time.Duration(s.agentRunSeconds(agentKey)) * time.Second
	out, err := ca.Chat(ctx, agentKey, sessionID, prompt, maxTurns, maxDuration, false, nil)
	if err != nil {
		if ctx.Err() != nil {
			return map[string]any{"reason": "superseded_by_newer_user_event"}, group.TermCancelled
		}
		return map[string]any{"error": sanitizeClientError(err.Error())}, group.TermFailed
	}
	return map[string]any{"text": out}, group.TermSettled
}

// groupMemberAgentKey returns a member's bound agent key ("" = unbound).
func groupMemberAgentKey(room *db.GroupRoom, memberID string) string {
	for _, m := range room.Members {
		if m.MemberID == memberID && m.AgentKey != "" {
			return m.AgentKey
		}
	}
	return ""
}

// agentProfileByKey returns an agent's bound LLM profile id (0 = unbound/missing).
func (s *Server) agentProfileByKey(key string) int64 {
	if s.m.pg == nil {
		return 0
	}
	ag, err := s.m.pg.GetAgentByKey(key)
	if err != nil || ag == nil || ag.LLMProfileID == nil {
		return 0
	}
	return *ag.LLMProfileID
}

func decodeJSON(r *http.Request, v any) error {
	return decode(r, v)
}
