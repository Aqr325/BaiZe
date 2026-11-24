package intercept

import "testing"

// convergeUnattended is the safety overlay: unattended mode must never auto-allow
// a downgraded judge decision, even if the operator previously configured
// fail_action / ask_timeout_action = allow.
func TestConvergeUnattendedForcesDeny(t *testing.T) {
	base := JudgeConfig{
		Enabled:           true,
		FailAction:        "allow",
		AskTimeoutAction:  "allow",
		AskTimeoutSeconds: 300,
	}

	// Unattended ON: a downgraded config must be converged to deny (fail-safe).
	got := convergeUnattended(base, true)
	if got.FailAction != "deny" {
		t.Errorf("unattended: FailAction = %q, want deny", got.FailAction)
	}
	if got.AskTimeoutAction != "deny" {
		t.Errorf("unattended: AskTimeoutAction = %q, want deny", got.AskTimeoutAction)
	}
	// Non-strategy fields must be untouched.
	if got.AskTimeoutSeconds != 300 || !got.Enabled {
		t.Errorf("unattended: non-strategy fields altered: %+v", got)
	}

	// Unattended OFF: saved config flows through untouched (operator is present).
	off := convergeUnattended(base, false)
	if off.FailAction != "allow" || off.AskTimeoutAction != "allow" {
		t.Errorf("attended: config should pass through, got %+v", off)
	}
}

// convergeUnattended is idempotent on an already-safe config (deny stays deny).
func TestConvergeUnattendedIdempotent(t *testing.T) {
	cfg := JudgeConfig{FailAction: "deny", AskTimeoutAction: "deny"}
	got := convergeUnattended(cfg, true)
	if got.FailAction != "deny" || got.AskTimeoutAction != "deny" {
		t.Errorf("idempotent: %+v", got)
	}
}

// Defaults are already safe (fail=ask, ask_timeout=deny); converging them in
// unattended mode must not change the ask_timeout (already deny) and must
// harden fail to deny (no human to answer an ask).
func TestConvergeUnattendedDefaults(t *testing.T) {
	cfg := JudgeConfig{FailAction: defaultJudgeFailAction, AskTimeoutAction: defaultJudgeAskTimeoutAction}
	got := convergeUnattended(cfg, true)
	if got.FailAction != "deny" {
		t.Errorf("defaults unattended: FailAction = %q, want deny", got.FailAction)
	}
	if got.AskTimeoutAction != defaultJudgeAskTimeoutAction {
		t.Errorf("defaults unattended: AskTimeoutAction = %q, want %q", got.AskTimeoutAction, defaultJudgeAskTimeoutAction)
	}
}
