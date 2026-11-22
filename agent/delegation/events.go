package delegation

import (
	"encoding/json"
	"sync"
	"time"
)

// EventKind is the type of one subagent event frame. It mirrors the framed
// event vocabulary of hermes' managed worker channel (managed_worker.py) plus
// the subagent_lifecycle event surface.
type EventKind string

const (
	// EventState is a subagent state transition.
	EventState EventKind = "state"
	// EventDelta is a streamed assistant text delta from the child.
	EventDelta EventKind = "delta"
	// EventToolStart is emitted when the child begins a tool call.
	EventToolStart EventKind = "tool.start"
	// EventToolComplete is emitted when the child finishes a tool call.
	EventToolComplete EventKind = "tool.complete"
	// EventActivity is the child's liveness heartbeat.
	EventActivity EventKind = "activity"
	// EventResult is the child's final bounded result.
	EventResult EventKind = "result"
	// EventError is a child-side failure with a redacted reason.
	EventError EventKind = "error"
)

// Event is one immutable frame published by a subagent. Data carries
// kind-specific payload (JSON-safe).
type Event struct {
	Kind       EventKind       `json:"kind"`
	SubagentID string          `json:"subagent_id"`
	Ts         float64         `json:"ts"`
	Data       map[string]any  `json:"data,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

// Broker fans subagent events to subscribers. It mirrors the owner/worker
// channel plus the live-log surface (delegation_live_log.py): each subagent
// publishes to a topic; the parent and any viewer subscribe to it.
type Broker struct {
	mu   sync.RWMutex
	subs map[string]map[int]chan Event
	next int
}

// NewBroker returns an empty event broker.
func NewBroker() *Broker {
	return &Broker{subs: map[string]map[int]chan Event{}}
}

// Subscribe returns a buffered channel receiving events for one subagent.
// Returns (ch, cancel). cancel must be called to release resources.
func (b *Broker) Subscribe(subagentID string, buffer int) (<-chan Event, func()) {
	if buffer < 1 {
		buffer = 64
	}
	ch := make(chan Event, buffer)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[subagentID] == nil {
		b.subs[subagentID] = map[int]chan Event{}
	}
	id := b.next
	b.next++
	b.subs[subagentID][id] = ch
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if m := b.subs[subagentID]; m != nil {
			delete(m, id)
		}
	}
}

// Publish sends one event to all subscribers of a subagent. Never blocks: a
// slow subscriber drops the event rather than stalling the child.
func (b *Broker) Publish(e Event) {
	b.mu.RLock()
	chans := make([]chan Event, 0, len(b.subs[e.SubagentID]))
	for _, c := range b.subs[e.SubagentID] {
		chans = append(chans, c)
	}
	b.mu.RUnlock()
	for _, c := range chans {
		select {
		case c <- e:
		default: // drop on slow subscriber
		}
	}
}

// PublishState publishes a state transition event.
func (b *Broker) PublishState(subagentID string, state State, extra map[string]any) {
	data := map[string]any{"state": string(state)}
	for k, v := range extra {
		data[k] = v
	}
	b.Publish(Event{Kind: EventState, SubagentID: subagentID, Ts: now(), Data: data})
}

// PublishResult publishes a child's final result frame.
func (b *Broker) PublishResult(subagentID string, r Result) {
	b.Publish(Event{Kind: EventResult, SubagentID: subagentID, Ts: now(), Data: map[string]any{"result": r}})
}

// PublishError publishes a redacted child failure.
func (b *Broker) PublishError(subagentID, reason string) {
	b.Publish(Event{Kind: EventError, SubagentID: subagentID, Ts: now(), Data: map[string]any{"reason": reason}})
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }
