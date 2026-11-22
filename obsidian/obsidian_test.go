package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFrontMatter(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantTitle string
		wantMeta  bool
		wantBody  string
	}{
		{"标准 frontmatter", "---\ntitle: XXE 打法\ntags: [lesson, web]\n---\n正文内容\n\n第二段", "XXE 打法", true, "正文内容\n\n第二段"},
		{"无 frontmatter", "就是纯正文，没有元数据", "", false, "就是纯正文，没有元数据"},
		{"CRLF 兼容", "---\r\ntitle: A\r\n---\r\nbody here", "A", true, "body here"},
		{"无闭合不解析", "---\ntitle: X\n没有闭合", "", false, "---\ntitle: X\n没有闭合"},
		{"闭合在文件尾无换行", "---\ntitle: X\n---", "X", true, ""},
		{"闭合在文件尾带空正文", "---\ntitle: X\n---\n", "X", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			meta, content := ParseFrontMatter(c.raw)
			if c.wantMeta != (meta != nil) {
				t.Fatalf("meta 存在性不符: want %v got %v", c.wantMeta, meta != nil)
			}
			if c.wantMeta {
				if got, _ := MetaString(meta, "title"); got != c.wantTitle {
					t.Errorf("title 不符: want %q got %q", c.wantTitle, got)
				}
			}
			if strings.TrimSpace(content) != strings.TrimSpace(c.wantBody) {
				t.Errorf("body 不符: want %q got %q", c.wantBody, content)
			}
		})
	}
}

func TestExtractWikilinks(t *testing.T) {
	text := "看 [[XXE 打法]] 和 [[XXE 打法|别名]]、[[内网#探测]]、[[笔记^block]] 以及 ![[嵌入]]，重复 [[XXE 打法]]。"
	got := ExtractWikilinks(text)
	want := []string{"XXE 打法", "内网", "笔记", "嵌入"}
	if len(got) != len(want) {
		t.Fatalf("应得 %v 个，得 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 个应 %q 得 %q", i, want[i], got[i])
		}
	}
	if len(ExtractWikilinks("没有链接")) != 0 {
		t.Errorf("无链接应返回空")
	}
}

func TestNoteHash(t *testing.T) {
	h1 := NoteHash("标题", "正文")
	h2 := NoteHash("标题", "正文")
	h3 := NoteHash("标题", "正文变了")
	if h1 != h2 {
		t.Errorf("相同内容哈希应一致")
	}
	if h1 == h3 {
		t.Errorf("内容变化哈希应不同")
	}
	if len(h1) != 64 {
		t.Errorf("SHA256 hex 应为 64 字符，得 %d", len(h1))
	}
}

func TestNoteScope(t *testing.T) {
	if got := NoteScope(map[string]any{"scope": "company"}, "global"); got != "company" {
		t.Errorf("frontmatter company 应生效，得 %s", got)
	}
	if got := NoteScope(map[string]any{"scope": "bogus"}, "global"); got != "global" {
		t.Errorf("非法 scope 应回退默认，得 %s", got)
	}
	if got := NoteScope(nil, "task"); got != "task" {
		t.Errorf("无 meta 用默认 task，得 %s", got)
	}
	if got := NoteScope(nil, "bogus"); got != "global" {
		t.Errorf("非法默认回退 global，得 %s", got)
	}
}

func TestNoteKind(t *testing.T) {
	if got := NoteKind(map[string]any{"kind": "lesson"}, nil); got != "lesson" {
		t.Errorf("frontmatter lesson 应生效，得 %s", got)
	}
	if got := NoteKind(nil, []string{"lesson", "web"}); got != "lesson" {
		t.Errorf("tags 含 lesson 应推断 lesson，得 %s", got)
	}
	if got := NoteKind(nil, []string{"preference"}); got != "preference" {
		t.Errorf("tags 含 preference 应推断，得 %s", got)
	}
	if got := NoteKind(nil, []string{"随便"}); got != "note" {
		t.Errorf("无匹配应默认 note，得 %s", got)
	}
}

func TestNoteSalience(t *testing.T) {
	if got := NoteSalience(map[string]any{"salience": 0.8}); got != 0.8 {
		t.Errorf("salience 0.8 应生效，得 %v", got)
	}
	if got := NoteSalience(map[string]any{"salience": 1.5}); got != 1.0 {
		t.Errorf("超上限应钳到 1，得 %v", got)
	}
	if got := NoteSalience(nil); got != 0.5 {
		t.Errorf("无 meta 应默认 0.5，得 %v", got)
	}
}

func TestTitleFromMeta(t *testing.T) {
	if got := TitleFromMeta(map[string]any{"title": "显式标题"}, "a/b/x.md"); got != "显式标题" {
		t.Errorf("应取显式标题，得 %s", got)
	}
	if got := TitleFromMeta(nil, "security/xxe.md"); got != "xxe" {
		t.Errorf("无 title 应取文件名，得 %s", got)
	}
}

func TestMetaTags(t *testing.T) {
	if got := MetaTags(map[string]any{"tags": []any{"a", "b"}}); len(got) != 2 || got[0] != "a" {
		t.Errorf("[]any tags 应解析，得 %v", got)
	}
	if got := MetaTags(map[string]any{"tags": "a, b, c"}); len(got) != 3 {
		t.Errorf("逗号分隔 tags 应解析，得 %v", got)
	}
	if got := MetaTags(nil); got != nil {
		t.Errorf("无 meta 应为 nil，得 %v", got)
	}
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	// 正常笔记。
	mustWrite(t, filepath.Join(dir, "a.md"), "---\ntitle: A\ntags: [fact]\n---\n内容 A\n[[B]]")
	// 子目录笔记。
	mustWrite(t, filepath.Join(dir, "sub", "b.md"), "# B 标题\n正文 B")
	// 非 md 忽略。
	mustWrite(t, filepath.Join(dir, "readme.txt"), "忽略我")
	// 排除目录。
	mustWrite(t, filepath.Join(dir, ".obsidian", "workspace.json"), `{}`)
	mustWrite(t, filepath.Join(dir, ".trash", "deleted.md"), "---\n---\n回收站")

	notes, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan 出错: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("应扫到 2 篇笔记，得 %d: %v", len(notes), notePaths(notes))
	}
	var a, b *Note
	for _, n := range notes {
		switch n.RelPath {
		case "a.md":
			a = n
		case "sub/b.md":
			b = n
		}
	}
	if a == nil {
		t.Fatalf("应含 a.md")
	}
	if a.Title != "A" || a.Hash == "" || len(a.Links) != 1 || a.Links[0] != "B" {
		t.Errorf("a.md 解析不符: %+v", a)
	}
	if b == nil {
		t.Fatalf("应含 sub/b.md")
	}
	if b.Title != "b" {
		t.Errorf("b.md 标题应取文件名 b，得 %s", b.Title)
	}
}

// 不存在目录应报错。
func TestScanMissingDir(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Errorf("不存在目录应返回错误")
	}
}

func TestParseNoteBody(t *testing.T) {
	n := Parse("x.md", "---\ntitle: X\nkind: lesson\n---\n结论：WAF 拦截\n", 100, 0)
	if n.KindOf() != "lesson" {
		t.Errorf("应映射为 lesson，得 %s", n.KindOf())
	}
}

// KindOf 是测试辅助：直接断言 NoteKind 结果。
func (n *Note) KindOf() string { return NoteKind(n.Meta, n.Tags) }

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func notePaths(notes []*Note) []string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.RelPath)
	}
	return out
}
