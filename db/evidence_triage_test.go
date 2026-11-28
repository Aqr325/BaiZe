package db

import "testing"

func TestHarmPrimitive(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"Apache 远程代码执行漏洞", HarmRCE},
		{"login 认证绕过", HarmAuthBypass},
		{"内核提权", HarmPrivEsc},
		{"未授权访问管理接口", HarmUnauthorized},
		{"任意文件上传导致 getshell", HarmFileWrite},
		{"SQL 注入", HarmInjection},
		{"SSRF 读取内网", HarmSSRF},
		{"敏感信息泄露", HarmInfoLeak},
		{"拒绝服务", HarmDoS},
		{"某常规配置问题", HarmOther},
	}
	for _, c := range cases {
		if got := HarmPrimitive(c.text); got != c.want {
			t.Errorf("HarmPrimitive(%q)=%q want %q", c.text, got, c.want)
		}
	}
}

func TestSpeculative(t *testing.T) {
	if !IsSpeculative("该漏洞尚未发现在野利用，暂无公开 PoC") {
		t.Error("应识别投机措辞")
	}
	if !IsSpeculative("预计可能出现利用代码") {
		t.Error("应识别预计/将来时")
	}
	if IsSpeculative("已确认在野利用，PoC 已公开并复现") {
		t.Error("不应误判为投机")
	}
}

func TestIsMultiCVESummary(t *testing.T) {
	if !IsMultiCVESummary("本周 CVE-2024-3094、CVE-2024-1234 等多漏洞综述") {
		t.Error("应识别多 CVE 综述")
	}
	if IsMultiCVESummary("CVE-2024-3094 单独漏洞分析") {
		t.Error("单 CVE 专题不应算综述")
	}
	if IsMultiCVESummary("CVE-2024-3094 与 CVE-2024-1234 对比分析") {
		t.Error("无综述特征词的不应算综述")
	}
}

func TestAssetTier(t *testing.T) {
	if got := AssetTier("internet firewall 边界防火墙"); got != AssetTierS {
		t.Errorf("边界防火墙应 Tier S, got %s", got)
	}
	if got := AssetTier("service nginx 反向代理"); got != AssetTierS {
		t.Errorf("nginx 应 Tier S, got %s", got)
	}
	if got := AssetTier("service Kubernetes 集群"); got != AssetTierS {
		t.Errorf("k8s 应 Tier S, got %s", got)
	}
	if got := AssetTier("service LLM 推理服务"); got != AssetTierA {
		t.Errorf("LLM 推理应 Tier A, got %s", got)
	}
	if got := AssetTier("subdomain app.example.com"); got != AssetTierB {
		t.Errorf("子域应 Tier B, got %s", got)
	}
	if got := AssetTier("endpoint ordinary"); got != AssetTierC {
		t.Errorf("普通端点应 Tier C, got %s", got)
	}
}

func TestMaxAssetTier(t *testing.T) {
	if got := MaxAssetTier([]string{AssetTierB, AssetTierS, AssetTierA}); got != AssetTierS {
		t.Errorf("应取 S, got %s", got)
	}
	if got := MaxAssetTier([]string{AssetTierB, AssetTierA}); got != AssetTierA {
		t.Errorf("应取 A, got %s", got)
	}
	if got := MaxAssetTier(nil); got != AssetTierC {
		t.Errorf("空应取 C, got %s", got)
	}
}

func TestTriageTier(t *testing.T) {
	if got := TriageTier("critical", EvidenceGradeRemoteVerified, HarmRCE, AssetTierS, "pending"); got != TriageTier1 {
		t.Errorf("remote+critical 未修复应 Tier1, got %d", got)
	}
	if got := TriageTier("high", EvidenceGradeRemoteVerified, HarmRCE, AssetTierB, "fixed"); got != TriageTier3 {
		t.Errorf("remote+fixed 应 Tier3, got %d", got)
	}
	if got := TriageTier("critical", EvidenceGradeLocalEffect, HarmRCE, AssetTierC, "pending"); got != TriageTier4 {
		t.Errorf("local+critical 高危 PoC 应 Tier4, got %d", got)
	}
	if got := TriageTier("critical", EvidenceGradeSelfClaim, HarmRCE, AssetTierS, "pending"); got != TriageTier5 {
		t.Errorf("核心资产高危严重自述应 Tier5(预警), got %d", got)
	}
	if got := TriageTier("low", EvidenceGradeSelfClaim, HarmOther, AssetTierC, "pending"); got != TriageTier6 {
		t.Errorf("低危应 Tier6, got %d", got)
	}
}

func TestHeadlineRank(t *testing.T) {
	// 新的高危核心资产漏洞应显著高于旧的低危普通漏洞。
	scoreNew, rationale := HeadlineRank("critical", EvidenceGradeRemoteVerified, HarmRCE, AssetTierS, "pending", 0, 48)
	if len(rationale) == 0 {
		t.Error("头条分必须附解释理由")
	}
	scoreOld := func() float64 {
		s, _ := HeadlineRank("low", EvidenceGradeSelfClaim, HarmOther, AssetTierC, "pending", 200, 48)
		return s
	}()
	if scoreNew <= scoreOld {
		t.Errorf("新核心漏洞应显著优先: new=%v old=%v", scoreNew, scoreOld)
	}
}

func TestGravityDecay(t *testing.T) {
	if d := GravityDecay(0, 48); d != 1 {
		t.Errorf("age=0 应 1, got %v", d)
	}
	if d := GravityDecay(48, 48); d != 0.5 {
		t.Errorf("age=halfLife 应 0.5, got %v", d)
	}
	if d := GravityDecay(96, 48); d != 0.25 {
		t.Errorf("age=2*halfLife 应 0.25, got %v", d)
	}
}
