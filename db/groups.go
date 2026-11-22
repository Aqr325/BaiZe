package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/baize/agent/group"
)

// GroupMember is one roster row with its BaiZe LLM binding. The LLM profile is
// what a member turn uses to run its Bot (hermes gives each Bot its own
// profile/model; BaiZe binds an llm_profiles row instead).
type GroupMember struct {
	group.Member
	LLMProfileID *int64 `json:"llm_profile_id,omitempty"`
	// AgentKey optionally binds this member to an existing agent; a member turn
	// then runs with that agent's system prompt (and its agent-level model when
	// the member has no explicit LLM binding).
	AgentKey string `json:"agent_key,omitempty"`
	Position int    `json:"position"`
}

// GroupRoom is the persisted projection of one hosted room.
type GroupRoom struct {
	Room        group.Room   `json:"room"`
	Image       string       `json:"image"`
	DisbandedAt *time.Time   `json:"disbanded_at,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Members     []GroupMember `json:"members"`
	// MemberCount is filled by ListGroupRooms (list view only); Members stays
	// empty there and is loaded by GetGroupRoom.
	MemberCount int `json:"member_count"`
}

// ErrGroupNotFound is returned when a room row is missing.
var ErrGroupNotFound = errors.New("group room not found")

// CreateGroupRoom inserts a room and its 2-6 member roster in one transaction.
// llmProfileByMember / agentKeyByMember are keyed by member_id (0/"" = unbound).
func (d *DB) CreateGroupRoom(room group.Room, image string, llmProfileByMember map[string]int64, agentKeyByMember map[string]string) error {
	if len(room.Members) < group.MinMembers || len(room.Members) > group.MaxMembers {
		return fmt.Errorf("group room needs %d-%d members", group.MinMembers, group.MaxMembers)
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO group_rooms
  (room_id, name, gateway_id, authority_epoch, routing, lead_member_id, purpose, notes, image)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		room.RoomID, room.Name, room.GatewayID, room.AuthorityEpoch,
		room.Routing, room.LeadMemberID, room.Purpose, room.Notes, image); err != nil {
		return err
	}
	for i, m := range room.Members {
		target, _ := json.Marshal(m.Target)
		var profileID any
		if id, ok := llmProfileByMember[m.MemberID]; ok && id > 0 {
			profileID = id
		}
		var agentKey any
		if k, ok := agentKeyByMember[m.MemberID]; ok && k != "" {
			agentKey = k
		}
		if _, err := tx.Exec(`INSERT INTO group_members
  (room_id, member_id, profile, handle, display_name, target, llm_profile_id, agent_key, position)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			room.RoomID, m.MemberID, m.Profile, m.Handle, m.DisplayName, string(target), profileID, agentKey, i); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetGroupRoom loads a room with its members (ErrGroupNotFound when missing).
func (d *DB) GetGroupRoom(roomID string) (*GroupRoom, error) {
	var (
		r        GroupRoom
		image    string
		disband  sql.NullTime
		created  time.Time
		updated  time.Time
		routing  string
		lead     string
		purpose  string
		notes    string
		gateway  string
		epoch    int
	)
	err := d.QueryRow(`SELECT room_id, name, gateway_id, authority_epoch, routing, lead_member_id,
       purpose, notes, image, disbanded_at, created_at, updated_at
FROM group_rooms WHERE room_id=$1`, roomID).Scan(
		&r.Room.RoomID, &r.Room.Name, &gateway, &epoch, &routing, &lead,
		&purpose, &notes, &image, &disband, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	r.Room.GatewayID, r.Room.AuthorityEpoch = gateway, epoch
	r.Room.Routing, r.Room.LeadMemberID, r.Room.Purpose, r.Room.Notes = routing, lead, purpose, notes
	r.Image, r.CreatedAt, r.UpdatedAt = image, created, updated
	if disband.Valid {
		t := disband.Time
		r.DisbandedAt = &t
	}
	members, err := d.GroupMembers(roomID)
	if err != nil {
		return nil, err
	}
	r.Members = members
	r.MemberCount = len(members)
	r.Room.Members = make([]group.Member, len(members))
	for i, m := range members {
		r.Room.Members[i] = m.Member
	}
	return &r, nil
}

// GroupMembers loads a room's roster ordered by position.
func (d *DB) GroupMembers(roomID string) ([]GroupMember, error) {
	rows, err := d.Query(`SELECT member_id, profile, handle, display_name, target, llm_profile_id, agent_key, position
FROM group_members WHERE room_id=$1 ORDER BY position`, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupMember{}
	for rows.Next() {
		var (
			m          GroupMember
			targetJSON string
			profileID  sql.NullInt64
			agentKey   sql.NullString
		)
		if err := rows.Scan(&m.MemberID, &m.Profile, &m.Handle, &m.DisplayName,
			&targetJSON, &profileID, &agentKey, &m.Position); err != nil {
			return nil, err
		}
		if targetJSON != "" && targetJSON != "{}" {
			var t group.Target
			if err := json.Unmarshal([]byte(targetJSON), &t); err == nil {
				m.Target = &t
			}
		}
		if m.Target == nil {
			m.Target = group.LocalTarget(m.Profile)
		}
		if profileID.Valid {
			id := profileID.Int64
			m.LLMProfileID = &id
		}
		if agentKey.Valid {
			m.AgentKey = agentKey.String
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListGroupRooms returns active rooms (newest first) with their member counts.
func (d *DB) ListGroupRooms() ([]GroupRoom, error) {
	rows, err := d.Query(`SELECT r.room_id, r.name, r.gateway_id, r.authority_epoch, r.routing,
       r.lead_member_id, r.purpose, r.notes, r.image, r.disbanded_at, r.created_at, r.updated_at,
       (SELECT COUNT(*) FROM group_members m WHERE m.room_id = r.room_id) AS member_count
FROM group_rooms r ORDER BY r.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupRoom{}
	for rows.Next() {
		var (
			r       GroupRoom
			image   string
			disband sql.NullTime
			created time.Time
			updated time.Time
			routing string
			lead    string
			purpose string
			notes   string
			gateway string
			epoch   int
			count   int
		)
		if err := rows.Scan(&r.Room.RoomID, &r.Room.Name, &gateway, &epoch, &routing, &lead,
			&purpose, &notes, &image, &disband, &created, &updated, &count); err != nil {
			return nil, err
		}
		r.Room.GatewayID, r.Room.AuthorityEpoch = gateway, epoch
		r.Room.Routing, r.Room.LeadMemberID, r.Room.Purpose, r.Room.Notes = routing, lead, purpose, notes
		r.Image, r.CreatedAt, r.UpdatedAt = image, created, updated
		if disband.Valid {
			t := disband.Time
			r.DisbandedAt = &t
		}
		r.MemberCount = count // list view: count only, Members loaded by GetGroupRoom
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateGroupRoom updates editable room settings (name/purpose/notes/routing/lead).
func (d *DB) UpdateGroupRoom(roomID string, name, purpose, notes, routing, leadMemberID string) error {
	_, err := d.Exec(`UPDATE group_rooms SET name=$2, purpose=$3, notes=$4, routing=$5,
       lead_member_id=$6 WHERE room_id=$1`, roomID, name, purpose, notes, routing, leadMemberID)
	return err
}

// DisbandGroupRoom marks a room disbanded (keeps its log for audit).
func (d *DB) DisbandGroupRoom(roomID string) error {
	_, err := d.Exec(`UPDATE group_rooms SET disbanded_at=now() WHERE room_id=$1`, roomID)
	return err
}

// AddGroupMember appends one roster entry (caller validates the 2-6 bound).
func (d *DB) AddGroupMember(roomID string, m group.Member, llmProfileID *int64, agentKey string) error {
	target, _ := json.Marshal(m.Target)
	var profileID any
	if llmProfileID != nil && *llmProfileID > 0 {
		profileID = *llmProfileID
	}
	var ak any
	if agentKey != "" {
		ak = agentKey
	}
	_, err := d.Exec(`INSERT INTO group_members
  (room_id, member_id, profile, handle, display_name, target, llm_profile_id, agent_key, position)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,(SELECT COALESCE(MAX(position),0)+1 FROM group_members WHERE room_id=$1))`,
		roomID, m.MemberID, m.Profile, m.Handle, m.DisplayName, string(target), profileID, ak)
	return err
}

// RemoveGroupMember removes one roster entry.
func (d *DB) RemoveGroupMember(roomID, memberID string) error {
	_, err := d.Exec(`DELETE FROM group_members WHERE room_id=$1 AND member_id=$2`, roomID, memberID)
	return err
}

// AppendGroupEvent appends one typed event and returns its room-local seq.
// seq is allocated atomically as COALESCE(MAX(seq),0)+1. The transaction takes
// a FOR UPDATE lock on the room row, serializing concurrent appends to the same
// room so MAX(seq)+1 never collides under READ COMMITTED (hermes room log is
// append-only and seq-monotonic; the caller may also hold a room mutex).
func (d *DB) AppendGroupEvent(roomID string, ev group.Event) (int, error) {
	actor, _ := json.Marshal(ev.Actor)
	payload, _ := json.Marshal(ev.Payload)
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT 1 FROM group_rooms WHERE room_id=$1 FOR UPDATE`, roomID); err != nil {
		return 0, err
	}
	var seq int
	err = tx.QueryRow(`INSERT INTO group_events
  (room_id, seq, event_id, kind, actor, payload, authority_gateway_id, authority_epoch)
VALUES ($1, (SELECT COALESCE(MAX(seq),0)+1 FROM group_events WHERE room_id=$1), $2,$3,$4,$5,$6,$7)
RETURNING seq`,
		roomID, ev.EventID, ev.Kind, string(actor), string(payload),
		ev.AuthorityGatewayID, ev.AuthorityEpoch).Scan(&seq)
	if err != nil {
		return 0, err
	}
	return seq, tx.Commit()
}

// ListGroupEvents returns the room log in seq order.
func (d *DB) ListGroupEvents(roomID string) ([]group.Event, error) {
	rows, err := d.Query(`SELECT seq, event_id, kind, actor, payload, authority_gateway_id, authority_epoch
FROM group_events WHERE room_id=$1 ORDER BY seq`, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []group.Event{}
	for rows.Next() {
		var (
			ev       group.Event
			actorS   string
			payloadS string
		)
		if err := rows.Scan(&ev.Seq, &ev.EventID, &ev.Kind, &actorS, &payloadS,
			&ev.AuthorityGatewayID, &ev.AuthorityEpoch); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(actorS), &ev.Actor)
		_ = json.Unmarshal([]byte(payloadS), &ev.Payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// LatestGroupSeq returns the newest seq in a room (0 when empty).
func (d *DB) LatestGroupSeq(roomID string) (int, error) {
	var seq int
	err := d.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM group_events WHERE room_id=$1`, roomID).Scan(&seq)
	return seq, err
}

// GroupEventsSince returns room events with seq > after (policy delta reads).
func (d *DB) GroupEventsSince(roomID string, after int) ([]group.Event, error) {
	rows, err := d.Query(`SELECT seq, event_id, kind, actor, payload, authority_gateway_id, authority_epoch
FROM group_events WHERE room_id=$1 AND seq > $2 ORDER BY seq`, roomID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []group.Event{}
	for rows.Next() {
		var (
			ev       group.Event
			actorS   string
			payloadS string
		)
		if err := rows.Scan(&ev.Seq, &ev.EventID, &ev.Kind, &actorS, &payloadS,
			&ev.AuthorityGatewayID, &ev.AuthorityEpoch); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(actorS), &ev.Actor)
		_ = json.Unmarshal([]byte(payloadS), &ev.Payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// normalizeHandle strips a leading '@' and lowercases (display/scan helper).
func normalizeHandle(h string) string {
	return strings.TrimPrefix(strings.ToLower(h), "@")
}
