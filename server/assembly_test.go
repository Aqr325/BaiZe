package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/baize/agent"
	"github.com/Autumn-27/baize/db"
	actool "github.com/Autumn-27/norma/tool"
)

// TestClaimToolNameIsolatesNamespaces verifies the MCP namespace guard: two
// different servers must not be able to claim the same fully-qualified tool name
// (which would silently shadow one server's tool with another's).
func TestPinDecision(t *testing.T) {
	cases := []struct {
		name                   string
		prev                   string
		hasBaseline            bool
		cur                    string
		readErr                error
		enforce                bool
		wantBlock, wantAdvance bool
	}{
		{"read error -> fail open, NO advance (审查高2: 不洗白投毒描述)", "", false, "new", errors.New("db down"), true, false, false},
		{"no baseline -> trust & advance", "", false, "new", nil, true, false, true},
		{"unchanged -> pass", "abc", true, "abc", nil, true, false, false},
		{"changed + enforce -> block", "abc", true, "def", nil, true, true, false},
		{"changed + no enforce -> warn & advance", "abc", true, "def", nil, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block, advance := pinDecision(c.prev, c.hasBaseline, c.cur, c.readErr, c.enforce)
			if block != c.wantBlock || advance != c.wantAdvance {
				t.Fatalf("got block=%v advance=%v, want block=%v advance=%v", block, advance, c.wantBlock, c.wantAdvance)
			}
		})
	}
}

func TestClaimToolNameIsolatesNamespaces(t *testing.T) {
	owners := map[string]string{}
	const full = "mcp__shared__run"

	if prev, collided := claimToolName(owners, full, "server-a"); collided || prev != "" {
		t.Fatalf("first claim: prev=%q collided=%v, want (\"\", false)", prev, collided)
	}
	if got := owners[full]; got != "server-a" {
		t.Fatalf("owner after first claim = %q, want server-a", got)
	}

	// same server re-claiming is idempotent (not a shadow attack)
	if prev, collided := claimToolName(owners, full, "server-a"); collided || prev != "server-a" {
		t.Fatalf("same-server re-claim: prev=%q collided=%v, want (server-a, false)", prev, collided)
	}

	// a different server claiming the same full name is a collision
	if prev, collided := claimToolName(owners, full, "server-b"); !collided || prev != "server-a" {
		t.Fatalf("cross-server claim: prev=%q collided=%v, want (server-a, true)", prev, collided)
	}
	if got := owners[full]; got != "server-a" {
		t.Fatalf("owner must stay server-a after rejected collision, got %q", got)
	}

	// distinct names from distinct servers are fine
	if prev, collided := claimToolName(owners, "mcp__shared__list", "server-b"); collided || prev != "" {
		t.Fatalf("distinct name: prev=%q collided=%v, want (\"\", false)", prev, collided)
	}
}

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetAgentSkillVisibility(ag.ID, orig) })

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(ag.ID, skillName, false) })

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}
