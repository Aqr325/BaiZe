// Package obsidian — 连接本地 Obsidian 知识库（借鉴 basic-memory 的本地优先思路）。
//
// Obsidian 知识库 = 一个本地目录（vault）里的 Markdown 笔记。每篇笔记是 .md 文件，
// 顶部可带 YAML frontmatter（tags / title / aliases / 自定义字段），正文用 [[wikilink]]
// 互相链接。本包做【纯解析】：读目录、拆 frontmatter、提取 wikilink、算内容哈希、
// 把笔记元数据映射成记忆的作用域/类型/重要度——不碰数据库，纯逻辑可单测。
//
// 白泽定位是 Go 单二进制 + 内嵌 PG + 离线，因此这里不依赖 Python 运行时、不依赖
// Obsidian 应用、不引入外部服务；只读 vault 目录里的 .md 文件。同步（落库）在
// db 包的 MemoryStore.SyncObsidian 完成。
package obsidian

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Note 是解析出的一篇 Obsidian 笔记。
type Note struct {
	// RelPath 是相对 vault 根的路径（如 "security/xxe.md"），用于追踪与去重。
	RelPath string `json:"rel_path"`
	// Title 是显示标题：frontmatter title > 文件名（去 .md）。
	Title string `json:"title"`
	// Body 是去掉了 frontmatter 的正文。
	Body string `json:"body"`
	// Meta 是 frontmatter 解析出的键值（无 frontmatter 时为 nil）。
	Meta map[string]any `json:"meta,omitempty"`
	// Tags 是 frontmatter 的 tags（字符串或字符串列表都支持）。
	Tags []string `json:"tags"`
	// Links 是正文里的 [[wikilink]] 目标（去重保序）。
	Links []string `json:"links"`
	// Hash 是 title+body 的 SHA256（内容指纹，用于增量判断）。
	Hash string `json:"hash"`
	// Size 是文件字节数。
	Size int64 `json:"size"`
	// Mtime 是文件修改时间（Unix 秒）。
	Mtime int64 `json:"mtime"`
}

// SourcePrefix 是同步时给记忆的来源前缀。
const SourcePrefix = "obsidian:"

// defaultExcludedDirs 是扫描时跳过的目录（相对 vault 根的第一段）。
// .obsidian（应用配置）/ .trash（回收站）/ .git 等不可能是笔记。
var defaultExcludedDirs = map[string]bool{
	".obsidian":    true, // Obsidian 应用配置
	".trash":       true, // 回收站
	".git":         true, // 版本库
	".hg":          true,
	".svn":         true,
	"node_modules": true, // npm 依赖里的 README 不是笔记
	".bundle":      true,
	".smart-env":   true,
	".workbuddy":   true, // WorkBuddy 工作区（memory 日志不是 Obsidian 笔记）
	".claudian":    true, // Claude 元数据
}

// Scan 递归读取 vault 目录下所有 .md 笔记（跳过排除目录）。
// 不存在的目录返回错误；空目录返回空切片。
func Scan(vault string) ([]*Note, error) {
	vault = strings.TrimSpace(vault)
	if vault == "" {
		return nil, os.ErrNotExist
	}
	// 预检根目录存在（WalkDir 对不存在的根不会走回调，这里显式报错）。
	if _, err := os.Stat(vault); err != nil {
		return nil, err
	}
	notes := []*Note{}
	err := filepath.WalkDir(vault, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// 单个文件读不到（权限等）就跳过，不中断整库扫描。
			return nil
		}
		if d.IsDir() {
			if path == vault {
				return nil
			}
			rel, rerr := filepath.Rel(vault, path)
			if rerr != nil {
				return nil
			}
			// 任意路径段命中排除目录就整棵子树跳过（深层 node_modules/.git 也不漏）。
			for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
				if defaultExcludedDirs[seg] {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		rel, rerr := filepath.Rel(vault, path)
		if rerr != nil {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		info, ierr := d.Info()
		var size, mtime int64
		if ierr == nil {
			size = info.Size()
			mtime = info.ModTime().Unix()
		}
		notes = append(notes, Parse(rel, string(raw), size, mtime))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].RelPath < notes[j].RelPath })
	return notes, nil
}

// Parse 把一篇 .md 原始内容解析成 Note。relPath 是相对 vault 根的路径。
func Parse(relPath, raw string, size, mtime int64) *Note {
	meta, content := ParseFrontMatter(raw)
	title := TitleFromMeta(meta, relPath)
	body := strings.TrimSpace(content)
	return &Note{
		RelPath: filepath.ToSlash(relPath),
		Title:   title,
		Body:    body,
		Meta:    meta,
		Tags:    MetaTags(meta),
		Links:   ExtractWikilinks(body),
		Hash:    NoteHash(title, body),
		Size:    size,
		Mtime:   mtime,
	}
}

// ParseFrontMatter 把 raw 拆成 frontmatter 元数据 + 正文。
// 只有以 "---\n" 开头且存在闭合 "---\n" 的才视为 frontmatter；否则 meta 为 nil。
func ParseFrontMatter(raw string) (map[string]any, string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasPrefix(raw, "---\n") {
		return nil, raw
	}
	rest := raw[4:]
	idx := strings.Index(rest, "\n---\n")
	sepLen := len("\n---\n")
	if idx < 0 {
		// 闭合在文件尾（无尾随换行）：分隔符只有 "\n---" 四个字节，
		// 正文起点必须按实际找到的分隔符长度算，否则越界 panic。
		if strings.HasSuffix(rest, "\n---") {
			idx = strings.LastIndex(rest, "\n---")
			sepLen = len("\n---")
		} else {
			return nil, raw
		}
	}
	fm := rest[:idx]
	content := rest[idx+sepLen:]
	meta := map[string]any{}
	if err := yaml.Unmarshal([]byte(fm), &meta); err != nil {
		return nil, raw
	}
	return meta, strings.TrimSpace(content)
}

var reWikilink = regexp.MustCompile(`\[\[([^\]]+)\]\]`)

// ExtractWikilinks 提取正文里的 [[wikilink]] 目标（去重保序）。
// 支持 [[note]]、[[note|alias]]、[[note#heading]]、[[note^block]]、![[embed]] 等形态，
// 一律取目标笔记名（去掉 ! 前缀、|别名、#标题、^块引用）。
func ExtractWikilinks(content string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range reWikilink.FindAllString(content, -1) {
		inner := m[2 : len(m)-2] // 去掉 [[ 和 ]]
		inner = strings.TrimPrefix(inner, "!")
		// 取 | 前（别名丢弃）。
		if i := strings.IndexByte(inner, '|'); i >= 0 {
			inner = inner[:i]
		}
		// 取 # 前（标题丢弃）。
		if i := strings.IndexByte(inner, '#'); i >= 0 {
			inner = inner[:i]
		}
		// 取 ^ 前（块引用丢弃）。
		if i := strings.IndexByte(inner, '^'); i >= 0 {
			inner = inner[:i]
		}
		inner = strings.TrimSpace(inner)
		if inner == "" {
			continue
		}
		if seen[inner] {
			continue
		}
		seen[inner] = true
		out = append(out, inner)
	}
	return out
}

// NoteHash 是内容指纹：title + \x00 + body 的 SHA256 hex。
func NoteHash(title, body string) string {
	h := sha256.Sum256([]byte(title + "\x00" + body))
	return hex.EncodeToString(h[:])
}

// TitleFromMeta 取标题：frontmatter title > 文件名（去 .md 扩展名）。
func TitleFromMeta(meta map[string]any, relPath string) string {
	if meta != nil {
		if t, ok := MetaString(meta, "title"); ok && strings.TrimSpace(t) != "" {
			return strings.TrimSpace(t)
		}
	}
	base := filepath.Base(filepath.ToSlash(relPath))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return base
}

// NoteScope 映射记忆作用域：frontmatter scope（合法时）> 默认 def。
func NoteScope(meta map[string]any, def string) string {
	if meta != nil {
		if s, ok := MetaString(meta, "scope"); ok {
			s = strings.ToLower(strings.TrimSpace(s))
			switch s {
			case "global", "company", "task":
				return s
			}
		}
	}
	switch def {
	case "global", "company", "task":
		return def
	default:
		return "global"
	}
}

// NoteKind 映射记忆类型：frontmatter kind（合法时）> 按 tags 推断 > note。
// 约定：tags 含 lesson 推断为 lesson（打法教训），含 preference 推断为 preference，
// 含 fact 推断为 fact，否则 note。
func NoteKind(meta map[string]any, tags []string) string {
	if meta != nil {
		if k, ok := MetaString(meta, "kind"); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			switch k {
			case "fact", "preference", "lesson", "note":
				return k
			}
		}
	}
	tagSet := map[string]bool{}
	for _, t := range tags {
		tagSet[strings.ToLower(strings.TrimSpace(t))] = true
	}
	switch {
	case tagSet["lesson"]:
		return "lesson"
	case tagSet["preference"]:
		return "preference"
	case tagSet["fact"]:
		return "fact"
	default:
		return "note"
	}
}

// NoteSalience 映射重要度：frontmatter salience（0~1，钳位）> 0.5。
func NoteSalience(meta map[string]any) float64 {
	if meta != nil {
		if v, ok := MetaFloat(meta, "salience"); ok {
			if v < 0 {
				return 0
			}
			if v > 1 {
				return 1
			}
			return v
		}
	}
	return 0.5
}

// MetaString 取 frontmatter 的字符串字段。
func MetaString(meta map[string]any, key string) (string, bool) {
	if meta == nil {
		return "", false
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t), true
	case int:
		return fmt.Sprintf("%d", t), true
	case int64:
		return fmt.Sprintf("%d", t), true
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), true
		}
		return fmt.Sprintf("%g", t), true
	case bool:
		return fmt.Sprintf("%t", t), true
	default:
		return "", false
	}
}

// MetaFloat 取 frontmatter 的数字字段。
func MetaFloat(meta map[string]any, key string) (float64, bool) {
	if meta == nil {
		return 0, false
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		var f float64
		if _, err := fmt.Sscan(t, &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

// MetaTags 取 frontmatter 的 tags：字符串或字符串列表都接受。
func MetaTags(meta map[string]any) []string {
	if meta == nil {
		return nil
	}
	v, ok := meta["tags"]
	if !ok || v == nil {
		return nil
	}
	out := []string{}
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range t {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case string:
		for _, s := range strings.Split(t, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
