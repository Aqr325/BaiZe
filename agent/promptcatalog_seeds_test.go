package agent

import (
	"strings"
	"testing"
)

// TestEnhancementAgentSeeds 验证三个增强角色的默认提示词与动态种子表一致且非空。
func TestEnhancementAgentSeeds(t *testing.T) {
	seeds := BuiltinPromptSeedsForDynamic()
	if len(seeds) != 3 {
		t.Fatalf("BuiltinPromptSeedsForDynamic 应含 3 个角色，实际 %d", len(seeds))
	}
	want := map[string]string{
		"batch_reporter": BatchReporterDefaultPrompt,
		"asset_recon":    AssetReconDefaultPrompt,
		"redteam":        RedTeamDefaultPrompt,
	}
	for key, tmpl := range want {
		got, ok := seeds[key]
		if !ok {
			t.Fatalf("动态种子缺少角色 %q", key)
		}
		if got != tmpl {
			t.Fatalf("角色 %q 种子与常量不一致", key)
		}
		if strings.TrimSpace(tmpl) == "" {
			t.Fatalf("角色 %q 默认提示词为空", key)
		}
	}
}

// TestEnhancementAgentPrompts 验证每个角色的默认提示词都声明了核心纪律（不越权/真实证据）。
func TestEnhancementAgentPrompts(t *testing.T) {
	cases := map[string]struct {
		tmpl     string
		mustHave []string
	}{
		"batch_reporter": {BatchReporterDefaultPrompt, []string{"汇总", "只基于真实证据", "不重复渗透"}},
		"asset_recon":    {AssetReconDefaultPrompt, []string{"资产测绘", "只在授权范围", "登记真实数据"}},
		"redteam":        {RedTeamDefaultPrompt, []string{"横向", "立足", "对抗式自检", "只在授权范围"}},
	}
	for key, c := range cases {
		for _, s := range c.mustHave {
			if !strings.Contains(c.tmpl, s) {
				t.Errorf("角色 %q 提示词缺少 %q", key, s)
			}
		}
	}
}
