// Package group replicates hermes-agent's hosted-room "group chat" policy
// (Bot Mode rooms) as a pure, I/O-free Go module. It mirrors
// gateway/hosted_room_discussion.py: a frozen local roster plus the complete
// typed room log yields at most one next member task. Nothing here touches the
// network, a model, or the database — callers (server layer) reconcile terminal
// driver rows into publication plans before asking for the next task.
package group

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---- Limits --------------------------------------------------------------

const (
	// MaxMembers / MinMembers bound a room's frozen roster (hermes: 2-6 Bots).
	MaxMembers = 6
	MinMembers = 2
	// DefaultMaxRounds / DefaultMaxMessages bound one user-send discussion.
	DefaultMaxRounds   = 3
	DefaultMaxMessages = 10
	// MaxDeltaLines caps the newest messages a member turn carries.
	MaxDeltaLines = 24
	// MaxUserTextBytes / MaxMemberTextBytes bound a single text payload.
	MaxUserTextBytes   = 64 * 1024
	MaxMemberTextBytes = 64 * 1024
	// MaxPromptBytes bounds one member turn prompt (driver.MAX_PROMPT_BYTES).
	MaxPromptBytes = 128 * 1024
	// MaxIdentifierChars bounds every identifier field.
	MaxIdentifierChars = 128
	// TruncatedReplyNotice marks a member reply cut at MaxMemberTextBytes.
	TruncatedReplyNotice = "\n\n[Reply truncated. Ask the Bot to share the full result as a file.]"
)

// Limits mirrors DiscussionLimits: finite per-user-send scheduling ceilings.
type Limits struct {
	MaxRounds   int
	MaxMessages int
}

// DefaultLimits returns the canonical hermes ceilings (3 rounds, 10 messages).
func DefaultLimits() Limits {
	return Limits{MaxRounds: DefaultMaxRounds, MaxMessages: DefaultMaxMessages}
}

// Validate rejects non-positive ceilings.
func (l Limits) Validate() error {
	if l.MaxRounds < 1 {
		return fmt.Errorf("hosted_rooms.discussion.max_rounds must be a positive integer")
	}
	if l.MaxMessages < 1 {
		return fmt.Errorf("hosted_rooms.discussion.max_messages must be a positive integer")
	}
	return nil
}

// ---- Typed event kinds ---------------------------------------------------

// Event kinds (hermes hosted_room_discussion typed room log).
const (
	MessageUser     = "message.user"
	MessageMember   = "message.member"
	TurnSettled     = "turn.settled"
	TurnFailed      = "turn.failed"
	TurnCancelled   = "turn.cancelled"
	TurnDeferred    = "turn.deferred"
	RoomActivity    = "room.activity"
	RoomStopRequest = "room.stop_requested"
	RoomContinued   = "room.continued"
	RoomRouted      = "room.routed"
	RoomAssignment  = "room.assignment"
)

// Decision statuses (hermes DecisionStatus).
const (
	StatusIdle    = "idle"
	StatusTask    = "task"
	StatusSettled = "settled"
	StatusBounded = "bounded"
	StatusRoute   = "route"
)

// Terminal statuses (hermes TerminalKind).
const (
	TermSettled   = "settled"
	TermFailed    = "failed"
	TermCancelled = "cancelled"
	TermDeferred  = "deferred"
)

// ---- Model ---------------------------------------------------------------

// Target mirrors the local/peer member target in hermes' DiscussionMember.
// A nil Target means the member is local (Kind "local", Profile == member.Profile).
type Target struct {
	Kind             string // "local" | "peer"
	Profile          string
	PeerID           string
	InstallationID   string
	CapabilityDigest string // sha256 hex, peers only
	// GatewayURL is the peer's A2A JSON-RPC endpoint (e.g. https://peer/a2a).
	// Peers only; empty means the peer cannot yet be reached cross-gateway.
	GatewayURL string
	// PeerToken is the optional Bearer token for the peer's A2A endpoint.
	PeerToken string
}

// IsPeer reports whether the target is a cross-gateway peer member.
func (t *Target) IsPeer() bool { return t != nil && t.Kind == "peer" }

// Member mirrors DiscussionMember: one immutable room participant.
type Member struct {
	MemberID    string
	Profile     string
	Handle      string
	DisplayName string
	Target      *Target
}

// LocalTarget builds the canonical local target for a member profile.
func LocalTarget(profile string) *Target { return &Target{Kind: "local", Profile: profile} }

// Room mirrors DiscussionRoom: the validated policy projection of one room.
type Room struct {
	RoomID         string
	Name           string
	Members        []Member
	GatewayID      string
	AuthorityEpoch int
	// Routing selects how the first round is chosen ("everyone" default, or a
	// router/lead flow). BaiZe implements "everyone"; lead routing is an opt-in.
	Routing      string
	LeadMemberID string
	Purpose      string
	Notes        string
}

// Actor is the typed event author ("user" | "member" | "gateway").
type Actor struct {
	Kind        string
	ID          string
	Profile     string
	DisplayName string
}

// Event is one typed room log entry.
type Event struct {
	Seq                int
	EventID            string
	Kind               string
	Actor              Actor
	Payload            map[string]any
	AuthorityGatewayID string
	AuthorityEpoch     int
}

// Text extracts the text field of a user/member message payload.
func (e Event) Text() string {
	if s, ok := e.Payload["text"].(string); ok {
		return s
	}
	return ""
}

// TaskIdentity mirrors HostedTaskIdentity: deterministic turn coordinates.
type TaskIdentity struct {
	RoomID   string
	TaskID   string
	ThreadID string
	TurnID   string
}

// TaskPlan mirrors DiscussionTaskPlan: one deterministic member turn.
type TaskPlan struct {
	Identity          TaskIdentity
	Payload           map[string]any
	DiscussionEventID string
	Member            Member
	MemberIndex       int
	RoundIndex        int
	SeenThroughSeq    int
}

// Decision mirrors DiscussionDecision: the result of replaying room policy.
type Decision struct {
	Status            string
	Reason            string
	DiscussionEventID string
	SourceEventSeq    int
	ThreadID          string
	Task              *TaskPlan
	Continues         int
}

// PublicationPlan mirrors PublicationPlan: ordered effects for one terminal task.
type PublicationPlan struct {
	TaskID       string
	TerminalKind string
	Events       []EventPlan
}

// EventPlan mirrors EventPlan: one idempotent room append.
type EventPlan struct {
	EventID            string
	Kind               string
	Actor              Actor
	Payload            map[string]any
	AuthorityGatewayID string
	AuthorityEpoch     int
}

// ---- Validation ----------------------------------------------------------

var mentionRe = regexp.MustCompile(`@([A-Za-z0-9][A-Za-z0-9._:-]*)`)

// turnIDRe mirrors _TURN_ID_RE: d<source>.r<round>.p<position>.s<seen>.m<member24hex>.
var turnIDRe = regexp.MustCompile(`^d([1-9][0-9]*)\.r([0-9]+)\.p([0-5])\.s([1-9][0-9]*)\.m([0-9a-f]{24})$`)

// Identifier validates an identifier field (common.identifier, max 128 chars).
func Identifier(value, label string) (string, error) {
	if value == "" || len(value) > MaxIdentifierChars {
		return "", fmt.Errorf("%s must be a bounded identifier", label)
	}
	return value, nil
}

// ValidateMember validates one roster entry against the known local profiles.
func ValidateMember(raw Member, index int, knownProfiles map[string]bool) (Member, error) {
	var err error
	if raw.MemberID, err = Identifier(raw.MemberID, fmt.Sprintf("member %d id", index)); err != nil {
		return Member{}, err
	}
	if raw.Profile, err = Identifier(raw.Profile, fmt.Sprintf("member %d profile", index)); err != nil {
		return Member{}, err
	}
	if raw.Handle, err = Identifier(raw.Handle, fmt.Sprintf("member %d handle", index)); err != nil {
		return Member{}, err
	}
	if len(strings.TrimSpace(raw.DisplayName)) > 80 {
		return Member{}, fmt.Errorf("member %d display_name is too long", index)
	}
	if raw.Target == nil {
		raw.Target = LocalTarget(raw.Profile)
	}
	switch raw.Target.Kind {
	case "local":
		if raw.Target.Profile != raw.Profile {
			return Member{}, fmt.Errorf("member %d local target profile does not match member profile", index)
		}
		if !knownProfiles[raw.Profile] {
			return Member{}, fmt.Errorf("member %d profile '%s' is not local to this gateway", index, raw.Profile)
		}
	case "peer":
		if raw.Target.Profile != raw.Profile {
			return Member{}, fmt.Errorf("member %d peer target profile does not match member profile", index)
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(raw.Target.CapabilityDigest) {
			return Member{}, fmt.Errorf("member %d capability_digest must be a sha256 digest", index)
		}
		if raw.Target.GatewayURL != "" && !regexp.MustCompile(`^https?://`).MatchString(raw.Target.GatewayURL) {
			return Member{}, fmt.Errorf("member %d gateway_url must be an http(s) endpoint", index)
		}
	default:
		return Member{}, fmt.Errorf("member %d target kind must be local or peer", index)
	}
	return raw, nil
}

// ValidateRoster validates a frozen 2-6 member roster (validate_roster).
func ValidateRoster(members []Member, localProfiles []string) ([]Member, error) {
	if len(members) < MinMembers || len(members) > MaxMembers {
		return nil, fmt.Errorf("members must contain between %d and %d entries", MinMembers, MaxMembers)
	}
	known := make(map[string]bool, len(localProfiles))
	for _, p := range localProfiles {
		known[p] = true
	}
	out := make([]Member, len(members))
	targets := map[string]bool{}
	handles := map[string]bool{"all": true, "everyone": true}
	ids := map[string]bool{}
	for i, raw := range members {
		m, err := ValidateMember(raw, i, known)
		if err != nil {
			return nil, err
		}
		targetKey := strings.ToLower(memberTargetJSON(m.Target))
		if targets[targetKey] {
			return nil, fmt.Errorf("member %d targets must be unique", i)
		}
		if handles[strings.ToLower(m.Handle)] {
			return nil, fmt.Errorf("member handles must be unique and cannot reserve @all or @everyone")
		}
		if ids[strings.ToLower(m.MemberID)] {
			return nil, fmt.Errorf("member ids must be unique")
		}
		targets[targetKey] = true
		handles[strings.ToLower(m.Handle)] = true
		ids[strings.ToLower(m.MemberID)] = true
		out[i] = m
	}
	return out, nil
}

// ValidateRoom projects a room row into the strict same-gateway policy shape.
func ValidateRoom(room Room, localProfiles []string) (Room, error) {
	var err error
	if room.RoomID, err = Identifier(room.RoomID, "room_id"); err != nil {
		return Room{}, err
	}
	if strings.TrimSpace(room.Name) == "" {
		return Room{}, fmt.Errorf("room name must be a non-empty string")
	}
	if len(room.Name) > 120 {
		return Room{}, fmt.Errorf("room name is too long")
	}
	if room.GatewayID, err = Identifier(room.GatewayID, "authority_gateway_id"); err != nil {
		return Room{}, err
	}
	if room.AuthorityEpoch < 1 {
		return Room{}, fmt.Errorf("authority_epoch must be a positive integer")
	}
	if room.Members, err = ValidateRoster(room.Members, localProfiles); err != nil {
		return Room{}, err
	}
	if room.Routing == "" {
		room.Routing = "everyone"
	}
	return room, nil
}

func memberTargetJSON(t *Target) string {
	b, _ := json.Marshal(t)
	return string(b)
}

// ---- Mention resolution --------------------------------------------------

// ResolveMentions resolves member handles deterministically against the roster
// (hermes resolve_mentions). @all/@everyone selects everyone; with defaultAll
// and no mention everyone is selected; otherwise only cited members answer.
func ResolveMentions(texts []string, members []Member, defaultAll bool) []Member {
	byHandle := make(map[string]Member, len(members))
	for _, m := range members {
		byHandle[strings.ToLower(m.Handle)] = m
	}
	mentioned := map[string]bool{}
	everyone := false
	for _, text := range texts {
		for _, match := range mentionRe.FindAllStringSubmatch(text, -1) {
			handle := strings.ToLower(match[1])
			if handle == "all" || handle == "everyone" {
				everyone = true
			} else if _, ok := byHandle[handle]; ok {
				mentioned[handle] = true
			}
		}
	}
	if everyone || (defaultAll && len(mentioned) == 0) {
		return members
	}
	out := []Member{}
	for _, m := range members {
		if mentioned[strings.ToLower(m.Handle)] {
			out = append(out, m)
		}
	}
	return out
}

// IsPassText reports whether a settled member result is Discussion silence
// (hermes is_pass_text): empty or "(pass)" / "pass" / "pass." case-insensitive.
func IsPassText(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" {
		return true
	}
	return regexp.MustCompile(`(?i)^\(?\s*pass\s*\)?\.?$`).MatchString(t)
}

// ---- Helpers -------------------------------------------------------------

// MemberByID returns the member with the given id, or nil.
func MemberByID(room Room, memberID string) *Member {
	for i := range room.Members {
		if room.Members[i].MemberID == memberID {
			return &room.Members[i]
		}
	}
	return nil
}

// MemberDigest mirrors _member_digest: sha256(member_id\0profile\0handle\0target)[:24].
func MemberDigest(m Member) string {
	target := memberTargetJSON(m.Target)
	h := sha256Hex(fmt.Sprintf("%s\x00%s\x00%s\x00%s", m.MemberID, m.Profile, m.Handle, target))
	return h[:24]
}

// Rotate returns members rotated by round_index (hermes _rotate).
func Rotate(members []Member, roundIndex int) []Member {
	if len(members) == 0 {
		return members
	}
	shift := roundIndex % len(members)
	out := make([]Member, 0, len(members))
	out = append(out, members[shift:]...)
	out = append(out, members[:shift]...)
	return out
}
