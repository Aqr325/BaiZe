package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/baize/agent"
	"github.com/Autumn-27/baize/agent/a2a"
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
	// peer 跨网关(A2A,可选):kind="peer" 时成员由其远端 gateway 执行。
	Kind             string `json:"kind"` // "local"(默认) | "peer"
	PeerID           string `json:"peer_id"`
	GatewayURL       string `json:"gateway_url"`       // 远端 A2A 端点(如 https://peer/a2a)
	PeerToken        string `json:"peer_token"`        // 远端 Bearer token
	CapabilityDigest string `json:"capability_digest"` // 64 hex;空则服务端生成
}

type groupCreateInput struct {
	Name    string             `json:"name"`
	Image   string             `json:"image"`
	Members []groupMemberInput `json:"members"`
	// Routing: "everyone"(默认,串行轮流) | "lead"(lead 路由,hermes v0.22.7)。
	Routing      string `json:"routing"`
	LeadMemberID string `json:"lead_member_id"` // routing=lead 时的 lead 成员 handle
}

// ---- room lifecycle ------------------------------------------------------

// groupProfiles returns the local roster profiles (peer members run on their
// own gateway and are excluded from the local-profile validation set).
func (s *Server) groupProfiles(room *db.GroupRoom) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range room.Members {
		if m.Target != nil && m.Target.IsPeer() {
			continue
		}
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
		Routing: "everyone",
	}
	if in.Routing == "lead" {
		room.Routing = "lead"
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
		target := group.LocalTarget(profile)
		if mi.Kind == "peer" {
			digest := strings.TrimSpace(mi.CapabilityDigest)
			if digest == "" {
				sum := sha256.Sum256([]byte(newGroupID()))
				digest = hex.EncodeToString(sum[:])
			}
			target = &group.Target{
				Kind:             "peer",
				Profile:          profile,
				PeerID:           strings.TrimSpace(mi.PeerID),
				GatewayURL:       strings.TrimSpace(mi.GatewayURL),
				PeerToken:        mi.PeerToken,
				CapabilityDigest: digest,
			}
		}
		room.Members = append(room.Members, group.Member{
			MemberID: "gm-" + newGroupID(), Profile: profile, Handle: handle,
			DisplayName: mi.DisplayName, Target: target,
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
	if room.Routing == "lead" {
		leadHandle := strings.TrimPrefix(strings.TrimSpace(in.LeadMemberID), "@")
		if leadHandle == "" {
			writeErr(w, 400, "lead 路由需要指定 lead_member_id")
			return
		}
		for _, m := range room.Members {
			if strings.EqualFold(m.Handle, leadHandle) {
				room.LeadMemberID = m.MemberID
				break
			}
		}
		if room.LeadMemberID == "" {
			writeErr(w, 400, "lead_member_id 未匹配任何成员")
			return
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
		Actor:              group.Actor{Kind: "user", ID: "human"},
		Payload:            map[string]any{"text": strings.TrimSpace(in.Text), "thread_id": threadID},
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
		Actor:              group.Actor{Kind: "user", ID: "human"},
		Payload:            map[string]any{"cancel_id": newGroupID()},
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
		Actor:              group.Actor{Kind: "user", ID: "human"},
		Payload:            map[string]any{"discussion_event_id": r.URL.Query().Get("discussion"), "seen_through_seq": 0},
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
		case group.StatusRoute:
			// Lead routing turn (hermes v0.22.7): run the lead, resolve the
			// @target it names, and publish a room.routed event. The decision is
			// never broadcast — only the assigned member answers next. An empty
			// target (no @handle / failed turn) is still published so the policy
			// planner falls back to the ordinary "everyone" path next round,
			// never looping on the lead.
			result, status := s.runGroupMemberTurn(ctx, room, dec.Task)
			target := ""
			if status == group.TermSettled {
				if text, ok := result["text"].(string); ok {
					target = group.LeadRouteTarget(text, room.Room)
				}
			}
			s.appendGroupEvent(roomID, group.Event{
				EventID: "drouted:" + newGroupID(), Kind: group.RoomRouted,
				Actor: group.Actor{Kind: "member", ID: dec.Task.Member.MemberID, Profile: dec.Task.Member.Profile},
				Payload: map[string]any{
					"discussion_event_id": dec.DiscussionEventID,
					"target_member_id":    target,
					"assigned_by":         dec.Task.Member.MemberID,
					"source_event_seq":    dec.SourceEventSeq,
					"lead_route_failed":   target == "",
				},
				AuthorityGatewayID: roomID, AuthorityEpoch: 1,
			})
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
	// Cross-gateway peer members run over A2A against their own gateway.
	if member.Target != nil && member.Target.IsPeer() {
		return s.runPeerMemberTurn(ctx, room, task)
	}
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

// a2aCard advertises this gateway's capabilities to A2A peers.
func (s *Server) a2aCard() a2a.AgentCard {
	return a2a.AgentCard{
		Name:        "baize-artex",
		Description: "BaZe ARTEX gateway (pentest agent orchestration)",
		Version:     "artex",
	}
}

// runPeerMemberTurn runs a cross-gateway peer member's reply over A2A: the room
// prompt is sent to the peer gateway's task/send endpoint, which executes its
// local Bot and returns a Task whose last text artifact is the reply.
func (s *Server) runPeerMemberTurn(ctx context.Context, room *db.GroupRoom, task *group.TaskPlan) (map[string]any, string) {
	target := task.Member.Target
	if target == nil || target.GatewayURL == "" {
		return map[string]any{"error": "peer 成员缺少 A2A gateway_url"}, group.TermFailed
	}
	prompt, _ := task.Payload["prompt"].(string)
	client := a2a.NewClient(target.GatewayURL, target.PeerToken)
	resp, err := client.SendTask(ctx, s.a2aCard(), a2a.Message{
		Role:  "agent",
		Parts: []a2a.Part{{Kind: a2a.PartText, Text: prompt}},
	})
	if err != nil {
		if ctx.Err() != nil {
			return map[string]any{"reason": "superseded_by_newer_user_event"}, group.TermCancelled
		}
		return map[string]any{"error": sanitizeClientError(err.Error())}, group.TermFailed
	}
	text := ""
	if len(resp.Artifacts) > 0 {
		text = resp.Artifacts[len(resp.Artifacts)-1].Text
	}
	if text == "" && resp.Message != nil {
		text = resp.Message.Text()
	}
	if text == "" {
		return map[string]any{"text": "(pass)"}, group.TermSettled
	}
	return map[string]any{"text": text}, group.TermSettled
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
