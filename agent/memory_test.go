package agent

import (
	"strings"
	"testing"
)

// 记忆注入的纯逻辑部分（格式化 / 排序 / 长度兜底 / 提示词装配）不依赖 PG，全量覆盖。
// MemoryBlock 钩子由 server 接到 memories 表，这里用假钩子验证装配路径。

func withMemoryBlock(t *testing.T, fn func(taskID int64) string) {
	t.Helper()
	old := MemoryBlock
	MemoryBlock = fn
	t.Cleanup(func() { MemoryBlock = old })
}

func TestFormatMemoryBlockEmpty(t *testing.T) {
	if got := FormatMemoryBlock(nil, 0); got != "" {
		t.Errorf("空记忆应返回空串（提示词零影响），得 %q", got)
	}
	if got := FormatMemoryBlock([]MemoryEntry{{Body: "   "}}, 0); got != "" {
		t.Errorf("空白正文应被忽略，得 %q", got)
	}
}

func TestFormatMemoryBlockSortsPreferencesFirst(t *testing.T) {
	entries := []MemoryEntry{
		{Kind: "fact", Title: "技术栈", Body: "目标用 nginx 1.24"},
		{Kind: "preference", Title: "报告语言", Body: "漏洞报告统一用中文，CVSS 3.1"},
		{Kind: "lesson", Title: "死路", Body: "上传点被扩展名白名单挡住，别再试"},
	}
	got := FormatMemoryBlock(entries, 4000)
	for _, want := range []string{"已沉淀记忆", "[preference] 报告语言", "[lesson] 死路", "[fact] 技术栈", "save_memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("块应含 %q，得:\n%s", want, got)
		}
	}
	// 用户偏好必须排在最前：它决定输出格式，晚到就是白到。
	if i := strings.Index(got, "[preference]"); i < 0 ||
		strings.Index(got, "[lesson]") < i || strings.Index(got, "[fact]") < strings.Index(got, "[lesson]") {
		t.Errorf("偏好/教训/事实应按优先级排序:\n%s", got)
	}
}

func TestFormatMemoryBlockFoldsNewlinesAndTitles(t *testing.T) {
	got := FormatMemoryBlock([]MemoryEntry{{Kind: "note", Body: "第一行\n第二行  三"}}, 4000)
	if strings.Contains(got, "\n第二行") {
		t.Errorf("正文换行应折叠成空格:\n%s", got)
	}
	if !strings.Contains(got, "第一行 第二行 三") {
		t.Errorf("折叠后应保留词序:\n%s", got)
	}
	noTitle := FormatMemoryBlock([]MemoryEntry{{Kind: "note", Title: "  ", Body: "无标题"}}, 4000)
	if !strings.Contains(noTitle, "- [note] 无标题") {
		t.Errorf("空标题应省略标题位:\n%s", noTitle)
	}
}

func TestFormatMemoryBlockRespectsBudget(t *testing.T) {
	long := strings.Repeat("长", 500)
	entries := []MemoryEntry{
		{Kind: "preference", Title: "偏好", Body: "用户偏好"},
		{Kind: "fact", Title: "一", Body: long},
		{Kind: "fact", Title: "二", Body: long},
		{Kind: "fact", Title: "三", Body: long},
	}
	got := FormatMemoryBlock(entries, 900)
	if n := len([]rune(got)); n > 1600 {
		t.Errorf("长度兜底应生效，得 %d 字符", n)
	}
	if !strings.Contains(got, "未注入") {
		t.Errorf("被截断时应说明还有几条没注入:\n%s", got)
	}
	if !strings.Contains(got, "recall_memories") {
		t.Errorf("应提示可用 recall_memories 召回:\n%s", got)
	}
}

func TestMemoryTailNilHook(t *testing.T) {
	withMemoryBlock(t, nil)
	if got := memoryTail(1); got != "" {
		t.Errorf("钩子未接线时应返回空串，得 %q", got)
	}
}

func TestMemoryTailTrimsWhitespace(t *testing.T) {
	withMemoryBlock(t, func(int64) string { return "  \n【块】\n " })
	if got := memoryTail(3); got != "【块】" {
		t.Errorf("应去除首尾空白，得 %q", got)
	}
}

func TestPromptTaskIDFromVars(t *testing.T) {
	if got := promptTaskID(PlannerVars{TaskID: 42}); got != 42 {
		t.Errorf("PlannerVars 应携带任务 id，得 %d", got)
	}
	if got := promptTaskID(WorkerVars{TaskID: 7}); got != 7 {
		t.Errorf("WorkerVars 应携带任务 id，得 %d", got)
	}
	if got := promptTaskID(MainVars{TaskID: 9}); got != 9 {
		t.Errorf("MainVars 应携带任务 id，得 %d", got)
	}
	if got := promptTaskID(GoalsVars{TaskID: 11}); got != 11 {
		t.Errorf("GoalsVars 应携带任务 id，得 %d", got)
	}
	// 未实现接口的变量（平台级聊天）→ 0 = 只见 global 记忆。
	if got := promptTaskID(chatVars{DataDir: "/d", Now: "now"}); got != 0 {
		t.Errorf("无任务上下文的变量应得 0，得 %d", got)
	}
}

// 端到端：接线记忆钩子后，renderSystem 必须在正文之后追加记忆块，且不被用户
// 可编辑的正文覆盖掉。
func TestRenderSystemAppendsMemory(t *testing.T) {
	withMemoryBlock(t, func(taskID int64) string {
		if taskID != 5 {
			t.Errorf("应按任务取记忆，得 %d", taskID)
		}
		return "【记忆】目标 WAF 拦 <script>"
	})
	got := renderSystem("planner", `提示词正文 {{.Goal}}`, PlannerVars{Goal: "拿下X", TaskID: 5})
	if !strings.Contains(got, "提示词正文 拿下X") {
		t.Errorf("正文渲染应保持，得 %q", got)
	}
	if !strings.Contains(got, "【记忆】目标 WAF 拦 <script>") {
		t.Errorf("应追加记忆块，得 %q", got)
	}
	if strings.Index(got, "【记忆】") < strings.Index(got, "提示词正文") {
		t.Errorf("记忆块应在正文之后:\n%s", got)
	}
}

// 记忆正文里的 {{ }} 不参与模板渲染：否则一条记着模板语法的记忆会炸掉整份提示词。
func TestRenderSystemMemoryIsNotTemplated(t *testing.T) {
	withMemoryBlock(t, func(int64) string { return "【记忆】规则写法 {{.Unknown}}" })
	if _, err := renderTmpl("【记忆】规则写法 {{.Unknown}}", PlannerVars{}); err == nil {
		t.Fatal("前置条件不成立：模板语法应渲染失败")
	}
	// 直接走 renderSystem 不应报错或退化到默认正文。
	got := renderSystem("planner", "正文", PlannerVars{TaskID: 1})
	if !strings.Contains(got, "{{.Unknown}}") {
		t.Errorf("记忆原文应原样出现，得 %q", got)
	}
	if !strings.Contains(got, "正文") {
		t.Errorf("正文不应被记忆破坏，得 %q", got)
	}
}

// 记忆块要排在 OPSEC 之前：安全约束必须落在提示词最末。
func TestRenderSystemMemoryBeforeOpsec(t *testing.T) {
	withMemoryBlock(t, func(int64) string { return "【记忆】M" })
	prev := OpsecEnabled
	OpsecEnabled = func() bool { return true }
	defer func() { OpsecEnabled = prev }()

	got := renderSystem("planner", "正文", PlannerVars{TaskID: 1})
	if !strings.Contains(got, "OPSEC") {
		t.Fatalf("开着 OPSEC 时应含 OPSEC 块:\n%s", got)
	}
	if !strings.Contains(got, "【记忆】") {
		t.Fatalf("应含记忆块:\n%s", got)
	}
	if strings.Index(got, "【记忆】") > strings.Index(got, "OPSEC") {
		t.Errorf("记忆块应在 OPSEC 之前:\n%s", got)
	}
}
