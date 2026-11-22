package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// 记忆库的纯逻辑部分（校验 / 归一化 / 指纹 / 检索词切分 / SQL 占位符）不依赖 PG，
// 这里全量覆盖。涉及 SQL 的读写路径需要 PG，走集成测试。

func TestNormalizeMemoryDefaultsAndTrims(t *testing.T) {
	in, err := NormalizeMemory(MemoryInput{Content: "  目标用 nginx 1.24  "})
	if err != nil {
		t.Fatalf("合法输入应通过: %v", err)
	}
	if in.Scope != MemoryScopeGlobal || in.Kind != MemoryKindNote || in.Source != "user" {
		t.Errorf("空字段应落到默认值，得 scope=%q kind=%q source=%q", in.Scope, in.Kind, in.Source)
	}
	if in.Salience != 0.5 {
		t.Errorf("未给重要度应默认 0.5，得 %v", in.Salience)
	}
	if in.Content != "目标用 nginx 1.24" {
		t.Errorf("正文应去除首尾空白，得 %q", in.Content)
	}
	if in.CompanyID != 0 || in.TaskID != 0 {
		t.Errorf("global 记忆不应带企业/任务归属，得 %v %v", in.CompanyID, in.TaskID)
	}
}

func TestNormalizeMemoryRejects(t *testing.T) {
	cases := []struct {
		name string
		in   MemoryInput
		want error
	}{
		{"空正文", MemoryInput{}, ErrMemoryEmpty},
		{"坏作用域", MemoryInput{Scope: "planet", Content: "x"}, ErrMemoryBadScope},
		{"坏类型", MemoryInput{Content: "x", Kind: "rumor"}, ErrMemoryBadKind},
		{"company缺企业", MemoryInput{Scope: "company", Content: "x"}, ErrMemoryBadScope},
		{"task缺任务", MemoryInput{Scope: "task", Content: "x"}, ErrMemoryBadScope},
	}
	for _, c := range cases {
		if _, err := NormalizeMemory(c.in); err == nil {
			t.Errorf("%s: 应报错", c.name)
		} else if !errors.Is(err, c.want) {
			t.Errorf("%s: 想 %v 得 %v", c.name, c.want, err)
		}
	}
}

func TestNormalizeMemoryScopeClearsCrossFields(t *testing.T) {
	// company 记忆不应顺带记一个任务；task 记忆不应顺带记一个企业。
	got, err := NormalizeMemory(MemoryInput{Scope: "company", CompanyID: 7, TaskID: 9, Content: "x"})
	if err != nil || got.TaskID != 0 || got.CompanyID != 7 {
		t.Errorf("company 作用域应清掉 task_id，得 %+v err=%v", got, err)
	}
	got, err = NormalizeMemory(MemoryInput{Scope: "task", CompanyID: 7, TaskID: 9, Content: "x"})
	if err != nil || got.CompanyID != 0 || got.TaskID != 9 {
		t.Errorf("task 作用域应清掉 company_id，得 %+v err=%v", got, err)
	}
}

func TestNormalizeMemoryClampsLengthAndSalience(t *testing.T) {
	long := make([]rune, MemoryContentMax+50)
	for i := range long {
		long[i] = '字'
	}
	in, err := NormalizeMemory(MemoryInput{Content: string(long), Salience: 5})
	if err != nil {
		t.Fatalf("超长正文应被截断而非拒绝: %v", err)
	}
	if n := len([]rune(in.Content)); n > MemoryContentMax+1 { // +1 是截断标记
		t.Errorf("正文应截到上限，得 %d 字符", n)
	}
	if in.Salience != 1 {
		t.Errorf("重要度应夹紧到 1，得 %v", in.Salience)
	}
}

func TestMemoryFingerprintIsContentDrivenAndStable(t *testing.T) {
	base := memoryFingerprint("task", 0, 5, "fact", "WAF 拦 <script>")
	if base != memoryFingerprint("task", 0, 5, "fact", "  WAF 拦   <script>  ") {
		t.Error("同一事实的不同空白/大小写写法应算同一条记忆")
	}
	if base == memoryFingerprint("task", 0, 5, "fact", "WAF 拦 <img>") {
		t.Error("不同正文不应同指纹")
	}
	if base == memoryFingerprint("task", 0, 6, "fact", "WAF 拦 <script>") {
		t.Error("不同任务的同名记忆不应同指纹")
	}
	if base == memoryFingerprint("company", 3, 0, "fact", "WAF 拦 <script>") {
		t.Error("不同作用域的同名记忆不应同指纹")
	}
	if base == memoryFingerprint("task", 0, 5, "lesson", "WAF 拦 <script>") {
		t.Error("不同类型不应同指纹（同一正文既是事实又是教训时须并存）")
	}
}

func TestSearchTermsDedupesAndLimits(t *testing.T) {
	got := searchTerms("  nginx NGINX <script> a waf waf 中文关键词 ")
	// 去重（nginx）+ 丢掉 1 字符词（a）+ 中文整串保留
	joined := ""
	for _, s := range got {
		joined += s + "|"
	}
	for _, want := range []string{"nginx|", "waf|", "中文关键词|"} {
		if !strings.Contains(joined, want) {
			t.Errorf("检索词应含 %q，得 %q", want, joined)
		}
	}
	if strings.Contains(joined, "a|") {
		t.Errorf("单字符词应被丢弃，得 %q", joined)
	}
	if len(searchTerms("")) != 0 {
		t.Error("空查询应得空关键词列表")
	}
}

func TestSearchTermsCapsAtEight(t *testing.T) {
	many := "aa bb cc dd ee ff gg hh ii jj"
	if n := len(searchTerms(many)); n != 8 {
		t.Errorf("关键词应封顶 8 个，得 %d", n)
	}
}

func TestItoa64(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0"}, {1, "1"}, {10, "10"}, {42, "42"}, {1000, "1000"}} {
		if got := itoa64(c.in); got != c.want {
			t.Errorf("itoa64(%d)=%q 想 %q", c.in, got, c.want)
		}
	}
}

func TestToInt64Array(t *testing.T) {
	if got := toInt64Array([]int64{1, 2, 300}); got != "{1,2,300}" {
		t.Errorf("toInt64Array=%q", got)
	}
	if got := toInt64Array(nil); got != "{}" {
		t.Errorf("空数组应得 {}，得 %q", got)
	}
}

func TestMemoryCapForScope(t *testing.T) {
	if memoryCapForScope(MemoryScopeGlobal) != MemoryCapGlobal ||
		memoryCapForScope(MemoryScopeCompany) != MemoryCapCompany ||
		memoryCapForScope(MemoryScopeTask) != MemoryCapTask ||
		memoryCapForScope("???") != MemoryCapGlobal {
		t.Error("作用域上限映射不对")
	}
}

func TestScopeWherePredicate(t *testing.T) {
	// 可见范围谓词：global 恒在，company 只看本企业，task 只看本任务。
	where, n := scopeWhere(intPtr(7), intPtr(5), 1)
	if n != 3 {
		t.Errorf("下一个占位符序号应推进到 3，得 %d", n)
	}
	for _, want := range []string{"m.scope='global'", "m.company_id=$1", "m.task_id=$2"} {
		if !strings.Contains(where, want) {
			t.Errorf("谓词应含 %q，得 %q", want, where)
		}
	}
	where, n = scopeWhere(nil, nil, 5)
	if n != 7 || !strings.Contains(where, "$5") || !strings.Contains(where, "$6") {
		t.Errorf("无上下文时仍须生成占位符，得 %q next=%d", where, n)
	}
}

func intPtr(v int64) *int64 { return &v }

// TestPruneKeepsHighestScoring 验证裁剪方向：超出上限时必须保留重要度最高、
// 淘汰最弱的记忆。回归自「ORDER BY score ASC + OFFSET cap」曾反向删除高价值记忆。
func TestPruneKeepsHighestScoring(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	ms := d.Memories()
	marker := fmt.Sprintf("prune-test-%d", time.Now().UnixNano())
	// 插入 cap+2 条；salience 随序号递增，最后两条最重要。
	total := MemoryCapGlobal + 2
	for i := 0; i < total; i++ {
		if _, _, err := ms.Put(ctx, MemoryInput{
			Scope: MemoryScopeGlobal, Kind: MemoryKindNote,
			Content:  fmt.Sprintf("%s-item-%03d", marker, i),
			Salience: float64(i) / float64(total), Source: "test",
		}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	// 无论谁先清理，测试结束都抹掉本用例数据。
	defer func() {
		_, _ = d.Exec(`DELETE FROM memories WHERE content LIKE $1`, marker+"-%")
	}()

	deleted, err := ms.Prune(ctx, MemoryScopeGlobal, 0, 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted < 2 {
		t.Fatalf("超出 %d 条应至少淘汰 2 条，实际 %d", MemoryCapGlobal, deleted)
	}
	// 最高 salience 的条目必须还在。
	rows, err := d.Query(`SELECT content FROM memories WHERE content LIKE $1 ORDER BY salience DESC LIMIT 2`, marker+"-%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	kept := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, c)
	}
	if len(kept) != 2 || kept[0] != fmt.Sprintf("%s-item-%03d", marker, total-1) ||
		kept[1] != fmt.Sprintf("%s-item-%03d", marker, total-2) {
		t.Errorf("最高分两条应保留，实际 %v", kept)
	}
}
