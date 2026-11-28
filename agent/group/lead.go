package group

import (
	"fmt"
	"strings"
)

// Lead routing (hermes v0.22.7, per-room opt-in, default OFF).
//
// When a room routes through a lead, and a user message names nobody, the lead
// Bot decides which member should answer. The decision is recorded as a
// room.routed event (target_member_id, assigned_by) and is never broadcast to
// the whole room — only the assigned member is asked to respond. Messages that
// name someone (@handle / @all / @everyone) bypass the lead entirely and follow
// the ordinary mention resolution.
//
// Failure handling: a lead routing turn that yields no resolvable target is
// published as room.routed with an empty target_member_id, and the discussion
// then falls back to the ordinary "everyone" round-robin path (one attempt,
// never an infinite lead loop).

// LeadRoutingActive reports whether lead routing is in force for this room:
// routing == "lead" and lead_member_id names a member on the roster.
func LeadRoutingActive(room Room, routing, leadMemberID string) bool {
	if routing == "" {
		routing = room.Routing
	}
	if leadMemberID == "" {
		leadMemberID = room.LeadMemberID
	}
	if routing != "lead" || leadMemberID == "" {
		return false
	}
	return MemberByID(room, leadMemberID) != nil
}

// RoutedTarget returns the member a lead assigned for the given discussion, or
// "" when the discussion has no room.routed event yet. A non-empty result with
// an empty string target means "routing attempted but yielded nobody" (the
// caller should fall back to the ordinary path).
func RoutedTarget(validated []ValidatedEvent, discussionEventID string) (target string, attempted bool) {
	for _, e := range validated {
		if e.Kind != RoomRouted {
			continue
		}
		if str(e.Payload, "discussion_event_id") != discussionEventID {
			continue
		}
		return str(e.Payload, "target_member_id"), true
	}
	return "", false
}

// MemberAnsweredIn reports whether a member has already posted a committed
// message in this discussion (memberMessages is the discussion-scoped list).
func MemberAnsweredIn(memberMessages []ValidatedEvent, memberID string) bool {
	for _, e := range memberMessages {
		if eventMemberID(e) == memberID {
			return true
		}
	}
	return false
}

// LeadRouteTarget extracts the assigned member id from a lead routing turn's
// reply text. The lead replies with exactly one @handle. "@all"/"@everyone"
// and unresolvable mentions yield "" (no assignment). Pure, deterministic.
func LeadRouteTarget(text string, room Room) string {
	for _, match := range mentionRe.FindAllStringSubmatch(text, -1) {
		handle := strings.ToLower(match[1])
		if handle == "all" || handle == "everyone" {
			continue
		}
		if m := memberByHandle(room, handle); m != nil {
			return m.MemberID
		}
	}
	return ""
}

// LeadRoutePrompt builds the routing instruction prompt a lead receives when it
// must pick who answers (room purpose / shared notes / roster context included).
func LeadRoutePrompt(room Room, discussion ValidatedEvent, lead Member, context map[string]string) string {
	others := make([]string, 0, len(room.Members)-1)
	for _, m := range room.Members {
		if m.MemberID != lead.MemberID {
			others = append(others, "@"+m.Handle)
		}
	}
	lines := []string{
		fmt.Sprintf("[Discussion: %q] You are the room lead @%s.", room.Name, lead.Handle),
		"",
		"The user's message below names no one, so you decide which member answers it.",
		"Reply with exactly one @handle of the member who should answer.",
		"Members: " + strings.Join(others, ", "),
	}
	if purpose := context["purpose"]; purpose != "" {
		lines = append(lines, "Room purpose: "+purpose)
	}
	if notes := context["notes"]; notes != "" {
		lines = append(lines, "Shared notes: "+notes)
	}
	lines = append(lines, "", "New message:", "  "+formatMessage(discussion, room))
	return strings.Join(lines, "\n")
}

// memberByHandle returns the member with the given (case-insensitive) handle.
func memberByHandle(room Room, handle string) *Member {
	for i := range room.Members {
		if strings.EqualFold(room.Members[i].Handle, handle) {
			return &room.Members[i]
		}
	}
	return nil
}
