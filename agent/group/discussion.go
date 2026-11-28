package group

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// TurnRound returns the 0-based round a Discussion turn id names (hermes turn_round).
func TurnRound(turnID string) (int, bool) {
	m := turnIDRe.FindStringSubmatch(turnID)
	if m == nil {
		return 0, false
	}
	var n int
	fmt.Sscanf(m[2], "%d", &n)
	return n, true
}

// ---- Replay helpers ------------------------------------------------------

// pendingDiscussion returns the oldest latest-per-thread user message that is
// not stopped and not yet completed (hermes _pending_discussion).
func pendingDiscussion(validated []ValidatedEvent) *ValidatedEvent {
	stoppedThrough := 0
	for _, e := range validated {
		if e.Kind == RoomStopRequest {
			stoppedThrough = e.Seq
		}
	}
	continuedAt := continuedThrough(validated)
	completed := map[string]bool{}
	for _, e := range validated {
		if e.Kind == RoomActivity {
			status := str(e.Payload, "status")
			discussionID := str(e.Payload, "discussion_event_id")
			if (status == "settled" || status == "bounded") && e.Seq > continuedAt[discussionID] {
				completed[discussionID] = true
			}
		}
	}
	latestByThread := map[string]ValidatedEvent{}
	for _, e := range validated {
		if e.Kind == MessageUser {
			latestByThread[str(e.Payload, "thread_id")] = e
		}
	}
	threads := make([]string, 0, len(latestByThread))
	for t := range latestByThread {
		threads = append(threads, t)
	}
	sortStrings(threads)
	for _, t := range threads {
		e := latestByThread[t]
		if e.Seq > stoppedThrough && !completed[e.EventID] {
			ev := e
			return &ev
		}
	}
	return nil
}

// continuedThrough returns discussion_event_id -> seq of the newest room.continued.
func continuedThrough(validated []ValidatedEvent) map[string]int {
	out := map[string]int{}
	for _, e := range validated {
		if e.Kind == RoomContinued {
			id := str(e.Payload, "discussion_event_id")
			seen := intVal(e.Payload, "seen_through_seq")
			if seen > out[id] {
				out[id] = seen
			}
		}
	}
	return out
}

// continueCount returns how many room.continued events a discussion received.
func continueCount(validated []ValidatedEvent, discussionEventID string) int {
	n := 0
	for _, e := range validated {
		if e.Kind == RoomContinued && str(e.Payload, "discussion_event_id") == discussionEventID {
			n++
		}
	}
	return n
}

// resumeRound returns the round to resume after a pause, or -1 when not paused.
// BaiZe does not implement pause/resume; the hermes path (router.resume_round)
// resolves to -1 so the "whole room picks back up" branch never fires.
func resumeRound(validated []ValidatedEvent, discussionEventID string, memberMessages []ValidatedEvent) int {
	return -1
}

// threadMessages splits the room log into (thread messages, since-discussion,
// this-discussion member messages) — hermes _thread_messages.
func threadMessages(validated []ValidatedEvent, discussion ValidatedEvent) (thread []ValidatedEvent, since []ValidatedEvent, member []ValidatedEvent) {
	threadID := str(discussion.Payload, "thread_id")
	committed := map[string]bool{}
	for _, e := range validated {
		if e.Kind == TurnSettled {
			if id := str(e.Payload, "message_event_id"); id != "" {
				committed[id] = true
			}
		}
	}
	for _, e := range validated {
		if str(e.Payload, "thread_id") != threadID {
			continue
		}
		if e.Kind == MessageUser || (e.Kind == MessageMember && committed[e.EventID]) {
			thread = append(thread, e)
			if e.Seq >= discussion.Seq {
				since = append(since, e)
			}
			if e.Kind == MessageMember && str(e.Payload, "discussion_event_id") == discussion.EventID {
				member = append(member, e)
			}
		}
	}
	return thread, since, member
}

// deriveMemberWatermarks returns (thread,member)->last seen seq from member messages.
func deriveMemberWatermarks(validated []ValidatedEvent) map[string]int {
	out := map[string]int{}
	for _, e := range validated {
		if e.Kind != MessageMember {
			continue
		}
		threadID := str(e.Payload, "thread_id")
		memberID := eventMemberID(e)
		if threadID != "" && memberID != "" {
			key := threadID + "|" + memberID
			if e.Seq > out[key] {
				out[key] = e.Seq
			}
		}
	}
	return out
}

// effectiveWatermarks returns (thread,member)->last seen seq (hermes _effective_watermarks).
func effectiveWatermarks(validated []ValidatedEvent, initial map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range initial {
		if v >= 0 {
			out[k] = v
		}
	}
	for k, v := range deriveMemberWatermarks(validated) {
		if v > out[k] {
			out[k] = v
		}
	}
	return out
}

// firstRoundResponders: a human message with no mention addresses everyone; a
// scheduled post pulls in only its cited members; a notice pulls in nobody
// (hermes _first_round_responders). BaiZe has no scheduler posts, so all user
// messages are human-authored (scheduled==nil -> defaultAll).
func firstRoundResponders(discussion ValidatedEvent, room Room) []Member {
	return ResolveMentions([]string{discussion.Text()}, room.Members, true)
}

// unaddressedMemberMentions returns peers explicitly cited by a Bot and not
// heard from afterward (hermes _unaddressed_member_mentions).
func unaddressedMemberMentions(messages []ValidatedEvent, room Room) []Member {
	citedAt := map[string]int{}
	lastPostAt := map[string]int{}
	for _, e := range messages {
		if e.Kind != MessageMember {
			continue
		}
		speaker := eventMemberID(e)
		lastPostAt[speaker] = e.Seq
		for _, m := range ResolveMentions([]string{e.Text()}, room.Members, false) {
			if m.MemberID != speaker {
				if e.Seq > citedAt[m.MemberID] {
					citedAt[m.MemberID] = e.Seq
				}
			}
		}
	}
	out := []Member{}
	for _, m := range room.Members {
		if cited, ok := citedAt[m.MemberID]; ok && lastPostAt[m.MemberID] <= cited {
			out = append(out, m)
		}
	}
	return out
}

// requiresDirectReply: only the user's initial address requires a reply
// (hermes _requires_direct_reply).
func requiresDirectReply(room Room, source *ValidatedEvent, member Member, roundIndex int) bool {
	if roundIndex != 0 || source == nil || source.Kind != MessageUser {
		return false
	}
	for _, m := range ResolveMentions([]string{source.Text()}, room.Members, false) {
		if m.MemberID == member.MemberID {
			return true
		}
	}
	return false
}

// ---- Prompt construction --------------------------------------------------

// PromptOpts mirrors the optional _build_prompt inputs.
type PromptOpts struct {
	ReplyRequired  bool
	Context        map[string]string
	AddressedByJob string
	AssignedBy     *Member
	Routed         bool
}

// contextLines renders room purpose and shared notes (hermes _context_lines).
func contextLines(context map[string]string) []string {
	lines := []string{}
	if context != nil {
		if context["purpose"] != "" {
			lines = append(lines, "Room purpose (set by the user): "+context["purpose"])
		}
		if context["notes"] != "" {
			lines = append(lines, "Room notes (shared with every member; the user keeps them in room settings):")
			for _, line := range strings.Split(context["notes"], "\n") {
				lines = append(lines, "  "+line)
			}
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	return lines
}

// formatMessage renders one log event for a member prompt (hermes _format_message).
func formatMessage(e ValidatedEvent, room Room) string {
	if e.Kind == MessageUser {
		return fmt.Sprintf("User (user): %s", e.Text())
	}
	text := e.Text()
	if e.Kind == MessageUser {
		return fmt.Sprintf("Scheduled job (automated post, not the user): %s", text)
	}
	m := MemberByID(room, eventMemberID(e))
	handle := "?"
	if m != nil {
		handle = m.Handle
	}
	return fmt.Sprintf("@%s: %s", handle, text)
}

// truncateUTF8Text cuts text to maxBytes, appending suffix when truncated
// (hermes _truncate_utf8_text, byte-aware with valid-UTF-8 prefix).
func truncateUTF8Text(value string, maxBytes int, suffix string) string {
	if len(value) <= maxBytes {
		return value
	}
	limit := maxBytes - len(suffix)
	if limit < 0 {
		limit = 0
	}
	// Trim to a valid UTF-8 prefix of at most limit bytes.
	prefix := value
	for len(prefix) > 0 && len(prefix) > limit {
		_, size := utf8.DecodeLastRuneInString(prefix)
		prefix = prefix[:len(prefix)-size]
	}
	if prefix == "" {
		return strings.TrimSpace(suffix)
	}
	return prefix + suffix
}

// BuildPrompt constructs one member turn prompt (hermes _build_prompt).
func BuildPrompt(room Room, member Member, messages []ValidatedEvent, watermark, seenThroughSeq int, opts PromptOpts) (string, error) {
	// Delta: the newest MAX_DELTA_LINES messages since the watermark.
	delta := []ValidatedEvent{}
	for _, e := range messages {
		if watermark < e.Seq && e.Seq <= seenThroughSeq {
			delta = append(delta, e)
		}
	}
	if len(delta) > MaxDeltaLines {
		delta = delta[len(delta)-MaxDeltaLines:]
	}
	peers := []string{}
	for _, c := range room.Members {
		if c.MemberID != member.MemberID {
			peers = append(peers, "@"+c.Handle)
		}
	}
	peerList := strings.Join(peers, ", ")
	if peerList == "" {
		peerList = "no other members"
	}
	opening := []string{
		fmt.Sprintf("[Discussion: %q] You are @%s, one participant with %s and the user.",
			room.Name, member.Handle, peerList),
		"",
	}
	opening = append(opening, contextLines(opts.Context)...)
	opening = append(opening, "New messages in this thread since your last turn (oldest first):")

	var addressed string
	switch {
	case opts.AssignedBy != nil:
		addressed = fmt.Sprintf("- The room lead @%s gave the user's message to you.", opts.AssignedBy.Handle)
	case opts.AddressedByJob != "":
		addressed = fmt.Sprintf("- The scheduled job %q addressed you.", opts.AddressedByJob)
	case opts.Routed:
		addressed = "- The room picked you to answer the user's message."
	default:
		addressed = "- The user directly addressed you."
	}

	participation := []string{}
	if opts.ReplyRequired || opts.AssignedBy != nil || opts.Routed {
		participation = []string{
			fmt.Sprintf("%s Reply with your answer, result, or concrete blocker.", addressed),
			`- Do not return "(pass)". If you cannot proceed, explain why and what you need from the user.`,
		}
	} else {
		participation = []string{
			fmt.Sprintf("%s Reply with one conversational message only when you have something new worth adding.", addressed),
			`- If you have nothing new to add, reply with exactly "(pass)".`,
		}
	}
	rules := []string{
		"",
		"Rules for this Discussion:",
	}
	rules = append(rules, participation...)
	rules = append(rules,
		"- Mention a teammate by handle to pull them into the next round; do not repeat points already made.",
		"- Never reveal content from private conversations. Your reply is published verbatim.")

	fixed := strings.Join(append(append([]string{}, opening...), rules...), "\n")
	available := MaxPromptBytes - len(fixed) - 1
	if available < 0 {
		available = 0
	}
	selected := []string{}
	for i := len(delta) - 1; i >= 0; i-- {
		line := "  " + formatMessage(delta[i], room)
		lineBytes := len(line) + 1
		if lineBytes > available {
			if len(selected) == 0 && available > 32 {
				selected = append(selected, truncateUTF8Text(line, available, ""))
			}
			selected = append(selected, "  [Earlier content omitted to fit this turn.]")
			break
		}
		selected = append(selected, line)
		available -= lineBytes
	}
	// reverse selected
	for i, j := 0, len(selected)-1; i < j; i, j = i+1, j-1 {
		selected[i], selected[j] = selected[j], selected[i]
	}
	prompt := strings.Join(append(append(opening, selected...), rules...), "\n")
	if len(prompt) > MaxPromptBytes {
		return "", fmt.Errorf("Discussion prompt exceeds the driver limit")
	}
	return prompt, nil
}

// ---- Task plan -----------------------------------------------------------

// makeTaskPlan mirrors _make_task_plan: deterministic turn coordinates.
func makeTaskPlan(room Room, discussion ValidatedEvent, member Member, memberIndex, roundIndex, seenThroughSeq int, prompt string, leadRouting bool) TaskPlan {
	turnID := fmt.Sprintf("d%d.r%d.p%d.s%d.m%s", discussion.Seq, roundIndex, memberIndex, seenThroughSeq, MemberDigest(member))
	seedMap := map[string]any{
		"discussion_event_id": discussion.EventID,
		"member_id":           member.MemberID,
		"member_index":        memberIndex,
		"room_id":             room.RoomID,
		"round_index":         roundIndex,
		"seen_through_seq":    seenThroughSeq,
		"source_event_seq":    discussion.Seq,
		"thread_id":           str(discussion.Payload, "thread_id"),
	}
	if !leadRouting {
		seedMap["prompt_sha256"] = sha256Hex(prompt)
	}
	seed := CompactJSON(seedMap)
	taskID := "dtask:" + sha256Hex(seed)[:48]
	payload := map[string]any{
		"target_member_id": member.MemberID,
		"target_profile":   member.Profile,
		"prompt":           prompt,
		"source_event_seq": discussion.Seq,
	}
	return TaskPlan{
		Identity: TaskIdentity{RoomID: room.RoomID, TaskID: taskID,
			ThreadID: str(discussion.Payload, "thread_id"), TurnID: turnID},
		Payload:           payload,
		DiscussionEventID: discussion.EventID,
		Member:            member,
		MemberIndex:       memberIndex,
		RoundIndex:        roundIndex,
		SeenThroughSeq:    seenThroughSeq,
	}
}

// ---- Core policy: plan_next_task ----------------------------------------

// PlanNextTask replays the complete room log and returns at most one next member
// task (hermes plan_next_task). roomContext is the room settings in force when
// the pending discussion opened. An error means the room/roster is invalid.
func PlanNextTask(roomValue Room, events []Event, localProfiles []string, limits Limits, roomContext map[string]any) (Decision, error) {
	if err := limits.Validate(); err != nil {
		return Decision{}, err
	}
	room, err := ValidateRoom(roomValue, localProfiles)
	if err != nil {
		return Decision{}, err
	}
	context := map[string]string{}
	if roomContext != nil {
		for _, k := range []string{"purpose", "notes", "routing", "lead_member_id"} {
			if v, ok := roomContext[k].(string); ok {
				context[k] = v
			}
		}
	}
	validated := ValidatedEvents(events, room)
	discussion := pendingDiscussion(validated)
	if discussion == nil {
		return Decision{Status: StatusIdle, Reason: "no_pending_user_event"}, nil
	}
	threadID := str(discussion.Payload, "thread_id")
	continues := continueCount(validated, discussion.EventID)
	maxRounds := limits.MaxRounds * (continues + 1)
	maxMessages := limits.MaxMessages * (continues + 1)
	decide := func(status, reason string, task *TaskPlan) Decision {
		return Decision{Status: status, Reason: reason, DiscussionEventID: discussion.EventID,
			SourceEventSeq: discussion.Seq, ThreadID: threadID, Task: task, Continues: continues}
	}
	threadMessages_, discussionMessages, memberMessages := threadMessages(validated, *discussion)
	if len(memberMessages) >= maxMessages {
		return decide(StatusBounded, "max_messages", nil), nil
	}
	// lead routing is an opt-in BaiZe extension; the default "everyone" path
	// never routes through a lead (routed==nil) and never runs a routing turn.
	terminals := map[string]bool{}
	for _, e := range validated {
		if IsTerminalKind(e.Kind) && str(e.Payload, "discussion_event_id") == discussion.EventID {
			terminals[fmt.Sprintf("%d|%s", intVal(e.Payload, "round_index"), eventMemberID(e))] = true
		}
	}
	watermarks := effectiveWatermarks(validated, nil)
	resume := resumeRound(validated, discussion.EventID, memberMessages)

	// ---- lead routing (hermes v0.22.7, per-room opt-in, default OFF) ----
	// Active only when routing=="lead", the lead is on the roster, and the user
	// message names nobody. Messages that name someone bypass the lead entirely.
	leadMode := LeadRoutingActive(room, context["routing"], context["lead_member_id"])
	// A message that names someone (@handle / @all / @everyone) bypasses the
	// lead entirely and follows the ordinary mention resolution (hermes v0.22.7:
	// the lead only picks when the message names nobody).
	namesSomeone := len(ResolveMentions([]string{discussion.Text()}, room.Members, false)) > 0
	startRound := 0
	if leadMode && !namesSomeone {
		target, attempted := RoutedTarget(validated, discussion.EventID)
		if !attempted {
			// No routing decision yet: the lead makes one routing turn.
			if lm := MemberByID(room, context["lead_member_id"]); lm != nil {
				prompt := LeadRoutePrompt(room, *discussion, *lm, context)
				task := makeTaskPlan(room, *discussion, *lm, 0, 0, discussion.Seq, prompt, true)
				return decide(StatusRoute, "lead_route", &task), nil
			}
		} else if target != "" {
			// Routing done: the assigned member answers (AssignedBy=lead) unless
			// they already spoke in this discussion.
			if tm := MemberByID(room, target); tm != nil && !MemberAnsweredIn(memberMessages, tm.MemberID) {
				watermark := watermarks[threadID+"|"+tm.MemberID]
				prompt, err := BuildPrompt(room, *tm, threadMessages_, watermark, discussion.Seq, PromptOpts{
					AssignedBy: MemberByID(room, context["lead_member_id"]),
					Context:    context,
				})
				if err != nil {
					return Decision{}, err
				}
				task := makeTaskPlan(room, *discussion, *tm, 0, 0, discussion.Seq, prompt, true)
				return decide(StatusTask, "lead_assigned", &task), nil
			}
			// Assigned member already answered → continue the ordinary @ flow
			// from round 1 (round 0 was the lead's assignment).
			startRound = 1
		}
		// attempted with an empty target, or no valid lead → fall back to everyone.
	}

	for roundIndex := startRound; roundIndex < maxRounds; roundIndex++ {
		var responders []Member
		if roundIndex == 0 {
			responders = firstRoundResponders(*discussion, room)
		} else {
			responders = unaddressedMemberMentions(discussionMessages, room)
		}
		if len(responders) == 0 && roundIndex == resume {
			responders = room.Members
		}
		for memberIndex, member := range Rotate(responders, roundIndex) {
			watermark := watermarks[threadID+"|"+member.MemberID]
			delta := []ValidatedEvent{}
			for _, e := range threadMessages_ {
				if e.Seq > watermark {
					delta = append(delta, e)
				}
			}
			if len(delta) == 0 {
				continue
			}
			if terminals[fmt.Sprintf("%d|%s", roundIndex, member.MemberID)] {
				continue
			}
			seenThroughSeq := delta[len(delta)-1].Seq
			prompt, err := BuildPrompt(room, member, threadMessages_, watermark, seenThroughSeq, PromptOpts{
				ReplyRequired: requiresDirectReply(room, discussion, member, roundIndex),
				Context:       context,
			})
			if err != nil {
				return Decision{}, err
			}
			task := makeTaskPlan(room, *discussion, member, memberIndex, roundIndex, seenThroughSeq, prompt, false)
			return decide(StatusTask, "member_turn", &task), nil
		}
		if !anyMemberInRound(roundIndex, memberMessages) {
			return decide(StatusSettled, "silent_round", nil), nil
		}
		if roundIndex == maxRounds-1 {
			return decide(StatusBounded, "max_rounds", nil), nil
		}
	}
	return decide(StatusBounded, "exhausted", nil), nil
}

func anyMemberInRound(roundIndex int, memberMessages []ValidatedEvent) bool {
	for _, e := range memberMessages {
		if intVal(e.Payload, "round_index") == roundIndex {
			return true
		}
	}
	return false
}

// ---- Core policy: plan_publication --------------------------------------

// PlanPublication plans idempotent room effects for one terminal driver task
// (hermes plan_publication). A newer user event in the same thread supersedes a
// late result with a deterministic cancellation.
func PlanPublication(roomValue Room, events []Event, task TaskPlan, status string, result map[string]any, localProfiles []string) (PublicationPlan, error) {
	room, err := ValidateRoom(roomValue, localProfiles)
	if err != nil {
		return PublicationPlan{}, err
	}
	if task.Identity.RoomID != room.RoomID {
		return PublicationPlan{}, fmt.Errorf("task belongs to a different room")
	}
	if MemberByID(room, task.Member.MemberID) == nil {
		return PublicationPlan{}, fmt.Errorf("task member is not in the frozen roster")
	}
	switch status {
	case TermSettled, TermFailed, TermCancelled, TermDeferred:
	default:
		return PublicationPlan{}, fmt.Errorf("invalid terminal publication status")
	}
	if status == TermDeferred {
		// execution_generation required; BaiZe defers are not produced yet.
		return PublicationPlan{}, fmt.Errorf("deferred publication is not supported")
	}
	validated := ValidatedEvents(events, room)
	newerSameThread := false
	for _, e := range validated {
		if e.Kind == MessageUser && e.Seq > intVal(task.Payload, "source_event_seq") &&
			str(e.Payload, "thread_id") == task.Identity.ThreadID {
			newerSameThread = true
		}
	}
	effective := status
	if newerSameThread && status != TermDeferred {
		effective = TermCancelled
	}
	var source *ValidatedEvent
	for i := range validated {
		if validated[i].EventID == task.DiscussionEventID {
			source = &validated[i]
			break
		}
	}
	// A direct-reply turn that passes fails: it did not answer the user.
	if effective == TermSettled && requiresDirectReply(room, source, task.Member, task.RoundIndex) &&
		IsPassText(terminalText(result, "text", "")) {
		effective = TermFailed
		result = map[string]any{"error": fmt.Sprintf("@%s was directly addressed but returned no visible reply.", task.Member.Handle)}
	}
	digest := strings.TrimPrefix(task.Identity.TaskID, "dtask:")
	terminalID := "dterminal:" + digest
	messageID := "dmessage:" + digest
	gateway := room.GatewayID
	epoch := room.AuthorityEpoch
	memberActor := Actor{Kind: "member", ID: task.Member.MemberID, Profile: task.Member.Profile}
	if task.Member.DisplayName != "" {
		memberActor.DisplayName = task.Member.DisplayName
	}
	coords := map[string]any{
		"discussion_event_id": task.DiscussionEventID,
		"member_id":           task.Member.MemberID,
		"member_index":        task.MemberIndex,
		"round_index":         task.RoundIndex,
		"task_id":             task.Identity.TaskID,
		"thread_id":           task.Identity.ThreadID,
		"turn_id":             task.Identity.TurnID,
	}
	eventsOut := []EventPlan{}
	switch effective {
	case TermSettled:
		text := truncateUTF8Text(terminalText(result, "text", ""), MaxMemberTextBytes, TruncatedReplyNotice)
		if IsPassText(text) {
			eventsOut = append(eventsOut, EventPlan{EventID: terminalID, Kind: TurnSettled, Actor: gatewayActor(gateway),
				Payload:            withExtra(coords, "seen_through_seq", task.SeenThroughSeq, "message_event_id", nil, "passed", true),
				AuthorityGatewayID: gateway, AuthorityEpoch: epoch})
		} else {
			eventsOut = append(eventsOut, EventPlan{EventID: messageID, Kind: MessageMember, Actor: memberActor,
				Payload:            withExtra(coords, "text", text),
				AuthorityGatewayID: gateway, AuthorityEpoch: epoch})
			eventsOut = append(eventsOut, EventPlan{EventID: terminalID, Kind: TurnSettled, Actor: gatewayActor(gateway),
				Payload:            withExtra(coords, "seen_through_seq", task.SeenThroughSeq, "message_event_id", messageID, "passed", false),
				AuthorityGatewayID: gateway, AuthorityEpoch: epoch})
		}
	case TermFailed:
		errorText := terminalText(result, "error", "member turn failed")
		eventsOut = append(eventsOut, EventPlan{EventID: terminalID, Kind: TurnFailed, Actor: gatewayActor(gateway),
			Payload:            withExtra(coords, "seen_through_seq", task.SeenThroughSeq, "error", errorText),
			AuthorityGatewayID: gateway, AuthorityEpoch: epoch})
	case TermCancelled:
		reason := terminalText(result, "reason", "member turn cancelled")
		eventsOut = append(eventsOut, EventPlan{EventID: terminalID, Kind: TurnCancelled, Actor: gatewayActor(gateway),
			Payload:            withExtra(coords, "seen_through_seq", task.SeenThroughSeq, "reason", reason),
			AuthorityGatewayID: gateway, AuthorityEpoch: epoch})
	}
	return PublicationPlan{TaskID: task.Identity.TaskID, TerminalKind: effective, Events: eventsOut}, nil
}

func gatewayActor(gatewayID string) Actor { return Actor{Kind: "gateway", ID: gatewayID} }

func terminalText(result map[string]any, field, fallback string) string {
	if result != nil {
		if v, ok := result[field].(string); ok && v != "" {
			return v
		}
		if v, ok := result["text"].(string); ok && v != "" && field != "text" {
			return v
		}
	}
	return fallback
}

// withExtra clones coords and appends extra fields. Values passed as (key, nil)
// pairs are omitted, matching hermes' conditional extras.
func withExtra(coords map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(coords)+len(kv)/2)
	for k, v := range coords {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		key := kv[i].(string)
		val := kv[i+1]
		if val != nil {
			out[key] = val
		}
	}
	return out
}

// sortStrings is a tiny sort.Strings wrapper kept local to avoid an extra import
// in callers; it is replaced by the standard sort in the same package.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// marshalAny is kept for parity with hermes' compact_json call sites.
func marshalAny(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
