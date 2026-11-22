package group

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// sha256Hex returns the lowercase hex sha256 of value (hermes hashlib).
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// CompactJSON marshals value without HTML escaping (hermes compact_json).
func CompactJSON(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}

// ValidatedEvent is an Event with its coordinates normalized for policy replay.
type ValidatedEvent struct {
	Event   Event
	Seq     int
	EventID string
	Kind    string
	Actor   Actor
	Payload map[string]any
}

// ValidatedEvents normalizes a raw event list, dropping unparseable entries and
// sorting by seq (the room log is append-only and seq-monotonic in practice).
func ValidatedEvents(events []Event, room Room) []ValidatedEvent {
	out := make([]ValidatedEvent, 0, len(events))
	for _, e := range events {
		if e.Seq < 1 || e.EventID == "" || e.Kind == "" {
			continue
		}
		out = append(out, ValidatedEvent{Event: e, Seq: e.Seq, EventID: e.EventID,
			Kind: e.Kind, Actor: e.Actor, Payload: e.Payload})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// TerminalKinds are the terminal turn event kinds.
var TerminalKinds = map[string]bool{
	TurnSettled: true, TurnFailed: true, TurnCancelled: true, TurnDeferred: true,
}

// IsTerminalKind reports whether kind is a terminal turn event.
func IsTerminalKind(kind string) bool { return TerminalKinds[kind] }

// Text extracts the text field of a user/member message payload.
func (e ValidatedEvent) Text() string {
	if s, ok := e.Payload["text"].(string); ok {
		return s
	}
	return ""
}

// str returns the string payload field or "".
func str(payload map[string]any, key string) string {
	if s, ok := payload[key].(string); ok {
		return s
	}
	return ""
}

// strOr returns the string payload field or fallback.
func strOr(payload map[string]any, key, fallback string) string {
	if s, ok := payload[key].(string); ok {
		return s
	}
	return fallback
}

// intVal returns the int payload field (from float64/string) or 0.
func intVal(payload map[string]any, key string) int {
	switch v := payload[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

// eventMemberID returns the member_id of a member-authored event.
func eventMemberID(e ValidatedEvent) string { return str(e.Payload, "member_id") }

// isMemberKind reports whether the event is a member message.
func isMemberKind(e ValidatedEvent) bool { return e.Kind == MessageMember }

// hasKindIn checks whether any event has the given kind.
func hasKindIn(events []ValidatedEvent, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}
