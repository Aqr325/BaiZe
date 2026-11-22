package db

// entities.go — 记忆的实体链接图谱（借鉴 mem0 的 entity linking + cognee 的图记忆）。
//
// 从记忆正文离线提取「技术实体」（IP / 域名 / 路径 / 文件 / 端口 / CVE / 版本），
// 跨记忆用同一实体名关联，检索时能按「这条记忆讲的是哪个目标」聚合。
// 提取是纯规则（正则），不依赖 LLM——白泽离线可用，不引入外部向量/图库。
//
// 与 memories.go 的关系：memories 表存「结论」，这里存「结论里的实体」及
// 「结论 × 实体」的多对多链接。删除记忆时 links 级联删；实体保留（ref_count
// 归零后仍留着，等下次再被引用时复用）。

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MemoryEntityKind 是实体分类。word 保留给用户显式打的标签，自动提取不产生它。
const (
	EntityKindIP      = "ip"
	EntityKindDomain  = "domain"
	EntityKindPath    = "path"
	EntityKindFile    = "file"
	EntityKindPort    = "port"
	EntityKindCVE     = "cve"
	EntityKindVersion = "version"
	EntityKindWord    = "word"
	// EntityKindNote 是 Obsidian 笔记 wikilink 目标（本地知识库的笔记链接）。
	EntityKindNote = "note"
)

// MemoryEntity 是图谱里的一个实体。
type MemoryEntity struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	RefCount  int    `json:"ref_count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// EntityHit 是提取出的一个实体命中（Name + Kind）。
type EntityHit struct {
	Name string
	Kind string
}

var (
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// 域名：至少一个点、末段纯字母 2+，排除纯 IP 形态（避免 1.2.3.4 当域名）。
	reDomain = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b`)
	// 路径：以 / 开头且至少两段（/a/b）。RE2 无 lookbehind，前导字母数字的
	// 相对路径（x/a/b）会从第二个 / 匹配——对记忆提取可接受。
	rePath = regexp.MustCompile(`/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)+`)
	// 文件：常见扩展名。
	reFile = regexp.MustCompile(`(?i)\b[A-Za-z0-9._-]+\.(php|jsp|aspx?|asp|js|json|xml|txt|bak|sql|exe|dll|conf|env|log|csv|zip|tar|gz|html?|ini|pem|key|db)\b`)
	// 端口：冒号后 2-5 位数字。前导字符是否为数字/点/冒号（IP 段、时间）在
	// 提取循环里用位置判断，RE2 不能做 lookbehind。
	rePort = regexp.MustCompile(`:\d{2,5}\b`)
	// CVE 编号。
	reCVE = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	// 版本号：x.y(.z...)，排除纯 IPv4（前面有 reIPv4 单独处理）。
	reVersion = regexp.MustCompile(`\bv?\d{1,3}\.\d{1,3}(?:\.\d{1,3})?(?:\.\d{1,3})?\b`)
)

// isIPv4 校验点分十进制每一段都在 0-255。
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// isDomain 排除纯 IP 形态的字符串（1.2.3.4 不该算域名）。
func isDomain(s string) bool {
	if isIPv4(s) {
		return false
	}
	return strings.Count(s, ".") >= 1
}

// extractEntities 从文本里离线提取技术实体，返回去重后的命中（按名称排序）。
// 纯规则、无 LLM：白泽离线可用的前提。不做 word 自动提取（避免噪音），
// word 由用户显式打标签。
func extractEntities(text string) []EntityHit {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]EntityHit{} // 小写 key -> 命中（保留原始大小写显示）
	claim := func(name, kind string) {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			return
		}
		if _, ok := seen[key]; !ok {
			seen[key] = EntityHit{Name: strings.TrimSpace(name), Kind: kind}
		}
	}

	for _, m := range reIPv4.FindAllString(text, -1) {
		if isIPv4(m) {
			claim(m, EntityKindIP)
		}
	}
	for _, m := range reDomain.FindAllString(text, -1) {
		if isDomain(m) {
			claim(m, EntityKindDomain)
		}
	}
	for _, m := range rePath.FindAllString(text, -1) {
		claim(m, EntityKindPath)
	}
	for _, m := range reFile.FindAllString(text, -1) {
		claim(m, EntityKindFile)
	}
	for _, m := range rePort.FindAllStringSubmatchIndex(text, -1) {
		start := m[0]
		// 前导字符是数字/点/冒号 = 属于 IP 段或时间戳，不是独立端口。
		if start > 0 {
			c := text[start-1]
			if (c >= '0' && c <= '9') || c == '.' || c == ':' {
				continue
			}
		}
		p := text[start+1 : m[1]]
		if n := len(p); n >= 2 && n <= 5 {
			claim(p, EntityKindPort)
		}
	}
	for _, m := range reCVE.FindAllString(text, -1) {
		claim(m, EntityKindCVE)
	}
	for _, m := range reVersion.FindAllString(text, -1) {
		if isIPv4(m) {
			continue
		}
		// 版本号不能是纯端口形态
		claim(m, EntityKindVersion)
	}

	out := make([]EntityHit, 0, len(seen))
	for _, h := range seen {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// SyncEntities 提取正文里的实体并重建该记忆的链接（删旧连新）。事务内完成。
func (s *MemoryStore) SyncEntities(ctx context.Context, memoryID int64, text string) error {
	return s.syncEntities(ctx, memoryID, extractEntities(text))
}

// SyncEntitiesWithLinks 提取正文里的技术实体，并额外把 Obsidian wikilink 目标
// （kind=note）一并建成实体链接——知识库的「笔记互相引用」也进图谱。
func (s *MemoryStore) SyncEntitiesWithLinks(ctx context.Context, memoryID int64, text string, wikilinks []string) error {
	hits := extractEntities(text)
	for _, l := range wikilinks {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		hits = append(hits, EntityHit{Name: l, Kind: EntityKindNote})
	}
	return s.syncEntities(ctx, memoryID, hits)
}

// syncEntities 重建一条记忆的实体链接（删旧连新）。hits 按 name 去重（同名取第一个
// kind），事务内完成。
func (s *MemoryStore) syncEntities(ctx context.Context, memoryID int64, hits []EntityHit) error {
	if memoryID <= 0 {
		return nil
	}
	// 按 name 去重：同名不同 kind 取第一个（域名优先于版本）。
	byName := map[string]EntityHit{}
	order := []string{}
	for _, h := range hits {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := byName[key]; ok {
			continue
		}
		byName[key] = EntityHit{Name: name, Kind: h.Kind}
		order = append(order, key)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM memory_entity_links WHERE memory_id=$1`, memoryID); err != nil {
		return err
	}
	for _, key := range order {
		h := byName[key]
		var eid int64
		if err := tx.QueryRowContext(ctx, `
INSERT INTO memory_entities(name, kind) VALUES($1, $2)
ON CONFLICT (name) DO UPDATE SET last_seen=now()
RETURNING id`, h.Name, h.Kind).Scan(&eid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO memory_entity_links(entity_id, memory_id) VALUES($1, $2)
ON CONFLICT DO NOTHING`, eid, memoryID); err != nil {
			return err
		}
	}
	// 重算每个受影响实体的引用数。
	if _, err := tx.ExecContext(ctx, `
UPDATE memory_entities e SET ref_count = (
  SELECT count(*) FROM memory_entity_links l WHERE l.entity_id = e.id)
WHERE e.id IN (SELECT entity_id FROM memory_entity_links WHERE memory_id=$1)`, memoryID); err != nil {
		return err
	}
	return tx.Commit()
}

// EntitiesForMemory 返回一条记忆关联的全部实体。
func (s *MemoryStore) EntitiesForMemory(ctx context.Context, memoryID int64) ([]MemoryEntity, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, e.name, e.kind, e.ref_count, e.first_seen::text, e.last_seen::text
FROM memory_entities e
JOIN memory_entity_links l ON l.entity_id = e.id
WHERE l.memory_id = $1
ORDER BY e.kind, e.name`, memoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MemoryEntity{}
	for rows.Next() {
		var e MemoryEntity
		if err := rows.Scan(&e.ID, &e.Name, &e.Kind, &e.RefCount, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEntities 列出实体库（管理界面/图谱浏览用），可按 kind 过滤。
func (s *MemoryStore) ListEntities(ctx context.Context, kind string, limit int) ([]MemoryEntity, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	q := `SELECT e.id, e.name, e.kind, e.ref_count, e.first_seen::text, e.last_seen::text
FROM memory_entities e`
	args := []any{}
	if kind != "" {
		q += ` WHERE e.kind=$1`
		args = append(args, kind)
	}
	q += ` ORDER BY e.ref_count DESC, e.name ASC LIMIT $` + itoa64(len(args)+1)
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MemoryEntity{}
	for rows.Next() {
		var e MemoryEntity
		if err := rows.Scan(&e.ID, &e.Name, &e.Kind, &e.RefCount, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// entityVisibleWhere 生成「该实体关联且当前可见」的记忆谓词，返回 SQL 片段与
// 是否真的需要实体过滤（空名 = 不过滤）。参数推进沿用 argStart。
func entityVisibleWhere(entity string, argStart int) (string, bool, int) {
	entity = strings.TrimSpace(entity)
	if entity == "" {
		return "", false, argStart
	}
	ph := fmt.Sprintf("$%d", argStart)
	return fmt.Sprintf(` AND m.id IN (
  SELECT l.memory_id FROM memory_entity_links l
  JOIN memory_entities e ON e.id = l.entity_id
  WHERE e.name = %s)`, ph), true, argStart + 1
}

// MemoryGraph 是单条记忆的图谱视图：记忆 + 其实体 + 实体关联到的其它记忆。
type MemoryGraph struct {
	Memory     *Memory        `json:"memory"`
	Entities   []MemoryEntity `json:"entities"`
	Related    []*Memory      `json:"related"`
	RelatedCnt int            `json:"related_count"`
}

// EntityGraph 返回某记忆的图谱：其实体，以及通过这些实体关联到的其它记忆
// （在同一可见范围内，去掉自身）。
func (s *MemoryStore) EntityGraph(ctx context.Context, memoryID, companyID, taskID int64, limit int) (*MemoryGraph, error) {
	m, err := s.Get(ctx, memoryID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	entities, err := s.EntitiesForMemory(ctx, memoryID)
	if err != nil {
		return nil, err
	}
	if len(entities) == 0 {
		return &MemoryGraph{Memory: m, Entities: entities, Related: []*Memory{}}, nil
	}
	names := make([]string, 0, len(entities))
	for _, e := range entities {
		names = append(names, e.Name)
	}
	var co, tk *int64
	if companyID > 0 {
		co = &companyID
	}
	if taskID > 0 {
		tk = &taskID
	}
	where, argN := scopeWhere(co, tk, 1)
	namesArg := argN
	limitArg := argN + 1
	qs := fmt.Sprintf(`
SELECT `+memoryCols+` FROM memories m
WHERE m.id <> $%d AND m.status='active' AND `+where+`
  AND m.id IN (
    SELECT l.memory_id FROM memory_entity_links l
    JOIN memory_entities e ON e.id = l.entity_id
    WHERE e.name = ANY($%d::text[]))
ORDER BY m.updated_at DESC
LIMIT $%d`, namesArg, namesArg, limitArg)
	rows, err := s.db.QueryContext(ctx, qs, memoryID, co, tk, toTextArray(names), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	related := []*Memory{}
	for rows.Next() {
		rm, err := scanMemory(rows)
		if err != nil {
			return nil, err
		}
		related = append(related, rm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &MemoryGraph{Memory: m, Entities: entities, Related: related, RelatedCnt: len(related)}, nil
}

// toTextArray 把 []string 转成 Postgres TEXT[] 字面量。
func toTextArray(ss []string) string {
	if len(ss) == 0 {
		return "{}"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "{" + strings.Join(parts, ",") + "}"
}
