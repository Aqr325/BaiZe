package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Memory 是平台沉淀的跨任务记忆：一条 = 一句可复用的事实、偏好或教训。
//
// 与 task_intelligence 的区别：intelligence 是一次探索的原始情报（挂在 task/node
// 下，随任务生命周期），Memory 是【提炼后值得长期记住的结论】——它跨任务存活，
// 在下一轮任务的系统提示词里直接生效。
//
// 三层 scope（记忆的作用域，决定谁能看见它）：
//   - global  平台级：用户偏好、通用经验。任何 agent 都读得到。
//   - company 企业级：某客户的特性（内网网段、OA 版本、审计要求）。
//   - task    任务级：本次目标的打法结论（WAF 拦什么、哪条链有效）。
//
// 写入幂等：同 scope/企业/任务/类型/正文的记忆撞 fingerprint 即刷新 updated_at
// （与 task_intelligence 同模式），重复写不会堆积重复条目。

const (
	MemoryScopeGlobal  = "global"
	MemoryScopeCompany = "company"
	MemoryScopeTask    = "task"

	MemoryKindFact       = "fact"       // 已观测事实：技术栈 / WAF / 认证 / 端口
	MemoryKindPreference = "preference" // 用户偏好：输出格式、语言、评级标准
	MemoryKindLesson     = "lesson"     // 经验教训：哪条路线为何封锁、什么手法有效
	MemoryKindNote       = "note"       // 其他备注

	MemoryStatusActive   = "active"
	MemoryStatusArchived = "archived"

	// memoryCap 是每个 scope 的条数上限：写入后超出即按综合分淘汰最弱的。
	// 上限的价值在「精炼」而非「囤积」——它同时兜住了注入提示词的长度。
	MemoryCapGlobal  = 200
	MemoryCapCompany = 400
	MemoryCapTask    = 600

	// MemoryContentMax 是单条正文上限（字符）。软截断而非拒绝：agent 一次性写出
	// 超长记忆时，宁可丢尾巴也不要整条作废。
	MemoryContentMax = 2000
	MemoryTitleMax   = 200
)

var (
	ErrMemoryEmpty     = errors.New("memory content is empty")
	ErrMemoryNotFound  = errors.New("memory not found")
	ErrMemoryBadScope  = errors.New("invalid memory scope")
	ErrMemoryBadKind   = errors.New("invalid memory kind")
	ErrMemoryBadStatus = errors.New("invalid memory status")
)

var (
	memoryScopes   = map[string]bool{MemoryScopeGlobal: true, MemoryScopeCompany: true, MemoryScopeTask: true}
	memoryKinds    = map[string]bool{MemoryKindFact: true, MemoryKindPreference: true, MemoryKindLesson: true, MemoryKindNote: true}
	memoryStatuses = map[string]bool{MemoryStatusActive: true, MemoryStatusArchived: true}
)

// Memory 是库里的一条记忆。
type Memory struct {
	ID         int64     `json:"id"`
	Scope      string    `json:"scope"`
	CompanyID  *int64    `json:"company_id,omitempty"`
	TaskID     *int64    `json:"task_id,omitempty"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	Salience   float64   `json:"salience"`
	HitCount   int       `json:"hit_count"`
	Status     string    `json:"status"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	// ValidFrom/ValidUntil 界定这条结论何时有效（mem0 时间感知）。
	// 两者皆 NULL = 长期有效；过期（valid_until <= now()）默认不被召回。
	ValidFrom  *time.Time `json:"valid_from,omitempty"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	// Score 只在打分查询里填充，库里没有这一列。
	Score float64 `json:"score,omitempty"`
}

// MemoryInput 是写入记忆的请求。CompanyID/TaskID 按 scope 选填：company 记忆
// 必须带 CompanyID，task 记忆必须带 TaskID，global 两者都不带。
type MemoryInput struct {
	Scope     string
	Kind      string
	Title     string
	Content   string
	Salience  float64
	Source    string
	CompanyID int64
	TaskID    int64
	// 时间感知：NULL = 即刻开始 / 长期有效。
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// MemoryFilter 是列表查询条件。空值 = 不过滤该维。
type MemoryFilter struct {
	Scope, Kind, Status, Q string
	CompanyID, TaskID      int64
	Limit, Offset          int
	// Entity 只列关联了某实体的记忆（图谱浏览）。
	Entity string
}

// MemorySearch 是召回查询：按关键词在可见范围内打分取 top-N。
type MemorySearch struct {
	Query     string
	CompanyID int64 // 0 = 无企业上下文（只见 global）
	TaskID    int64 // 0 = 无任务上下文（不含 task 级记忆）
	Limit     int
	// IncludeExpired 默认 false = 只召回当前有效的记忆（过期结论不打扰 agent）；
	// true = 连同过期的一起召回（显式「看历史」时用）。
	IncludeExpired bool
	// Entity 只召回关联了某实体的记忆（按目标聚合）。
	Entity string
}

// MemoryStat 是记忆库的分布统计（按 scope × kind）。
type MemoryStat struct {
	Scope string `json:"scope"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// MemoryPatch 是 PATCH 允许改的字段；空值 / nil = 不改。
type MemoryPatch struct {
	Title, Kind, Content, Status string
	Salience                     *float64
	ValidFrom                    *time.Time
	ValidUntil                   *time.Time
}

// memoryCols 是 SELECT 的统一列清单（顺序必须与 scanMemory 对应）。
const memoryCols = `m.id, m.scope, m.company_id, m.task_id, m.kind, m.title, m.content, m.salience,
 m.hit_count, m.status, m.source, m.created_at, m.updated_at, m.last_used_at, m.valid_from, m.valid_until`

// memoryColsPlain 与 memoryCols 同列序但**不带 m. 前缀**。
// 用于 INSERT/UPDATE 的 RETURNING（那里没有 FROM memories m，带前缀会 42P01）。
const memoryColsPlain = `id, scope, company_id, task_id, kind, title, content, salience,
 hit_count, status, source, created_at, updated_at, last_used_at, valid_from, valid_until`

func scanMemory(row interface{ Scan(...any) error }, withScore ...bool) (*Memory, error) {
	m := &Memory{}
	dest := []any{&m.ID, &m.Scope, &m.CompanyID, &m.TaskID, &m.Kind, &m.Title, &m.Content,
		&m.Salience, &m.HitCount, &m.Status, &m.Source, &m.CreatedAt, &m.UpdatedAt, &m.LastUsedAt,
		&m.ValidFrom, &m.ValidUntil}
	if len(withScore) > 0 {
		dest = append(dest, &m.Score)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	return m, nil
}

// memoryFingerprint 是「同一条记忆」的判定键：作用域 + 类型 + 归一化正文。
// 不含 title——标题是给人看的措辞，不该让换个标题就变成一条新记忆。
func memoryFingerprint(scope string, companyID, taskID int64, kind, content string) string {
	norm := strings.Join(strings.Fields(strings.ToLower(content)), " ")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s|%s", scope, companyID, taskID, kind, norm)))
	return hex.EncodeToString(sum[:])
}

// NormalizeMemory 校验并收敛一条记忆输入。
func NormalizeMemory(in MemoryInput) (MemoryInput, error) {
	in.Scope = strings.ToLower(strings.TrimSpace(in.Scope))
	if in.Scope == "" {
		in.Scope = MemoryScopeGlobal
	}
	if !memoryScopes[in.Scope] {
		return in, fmt.Errorf("%w: %q（应为 global|company|task）", ErrMemoryBadScope, in.Scope)
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if in.Kind == "" {
		in.Kind = MemoryKindNote
	}
	if !memoryKinds[in.Kind] {
		return in, fmt.Errorf("%w: %q（应为 fact|preference|lesson|note）", ErrMemoryBadKind, in.Kind)
	}
	in.Title = strings.TrimSpace(in.Title)
	in.Content = strings.TrimSpace(in.Content)
	if in.Content == "" {
		return in, ErrMemoryEmpty
	}
	if n := utf8.RuneCountInString(in.Title); n > MemoryTitleMax {
		in.Title = string([]rune(in.Title)[:MemoryTitleMax])
	}
	if n := utf8.RuneCountInString(in.Content); n > MemoryContentMax {
		in.Content = string([]rune(in.Content)[:MemoryContentMax]) + "…"
	}
	if in.Salience <= 0 {
		in.Salience = 0.5
	}
	if in.Salience > 1 {
		in.Salience = 1
	}
	in.Source = strings.TrimSpace(in.Source)
	if in.Source == "" {
		in.Source = "user"
	}
	// 作用域与归属必须自洽：company 记忆没有企业、task 记忆没有任务 = 写入即孤儿。
	switch in.Scope {
	case MemoryScopeCompany:
		if in.CompanyID <= 0 {
			return in, fmt.Errorf("%w: company 作用域需要 company_id", ErrMemoryBadScope)
		}
		in.TaskID = 0 // 企业级记忆不挂在具体任务上
	case MemoryScopeTask:
		if in.TaskID <= 0 {
			return in, fmt.Errorf("%w: task 作用域需要 task_id", ErrMemoryBadScope)
		}
		in.CompanyID = 0 // 任务级记忆不挂在具体企业上（企业上下文由 task_scope 解析）
	default: // global
		in.CompanyID, in.TaskID = 0, 0
	}
	return in, nil
}

// MemoryStore 读写记忆库。
type MemoryStore struct{ db *DB }

// Memories 返回记忆存储。
func (d *DB) Memories() *MemoryStore { return &MemoryStore{db: d} }

// scopeWhere 是「可见范围」谓词，Search/List/PromptMemories 共用。
// 语义：global 恒可见；company 仅在给定企业上下文时可见（避免跨客户泄露）；
// task 仅对本任务可见。传 nil 表示无该上下文。
func scopeWhere(companyID, taskID *int64, argStart int) (string, int) {
	co, tk := fmt.Sprintf("$%d", argStart), fmt.Sprintf("$%d", argStart+1)
	return fmt.Sprintf(`(m.scope='global' OR (m.scope='company' AND m.company_id=%s) OR (m.scope='task' AND m.task_id=%s))`, co, tk), argStart + 2
}

func scanMemoryCreated(row interface{ Scan(...any) error }) (*Memory, bool, error) {
	m := &Memory{}
	var created bool
	dest := []any{&m.ID, &m.Scope, &m.CompanyID, &m.TaskID, &m.Kind, &m.Title, &m.Content,
		&m.Salience, &m.HitCount, &m.Status, &m.Source, &m.CreatedAt, &m.UpdatedAt, &m.LastUsedAt,
		&m.ValidFrom, &m.ValidUntil, &created}
	if err := row.Scan(dest...); err != nil {
		return nil, false, err
	}
	return m, created, nil
}

// Put 写入一条记忆；撞 fingerprint 时刷新（重要度取较高值），返回 created=false。
// xmax 判据：刚插入的行 xmax=0，走 ON CONFLICT DO UPDATE 的行 xmax<>0，
// 用这一列区分「新建 / 命中已存在」，不需要额外查询。
func (s *MemoryStore) Put(ctx context.Context, in MemoryInput) (*Memory, bool, error) {
	in, err := NormalizeMemory(in)
	if err != nil {
		return nil, false, err
	}
	var co, tk *int64
	if in.CompanyID > 0 {
		co = &in.CompanyID
	}
	if in.TaskID > 0 {
		tk = &in.TaskID
	}
	fp := memoryFingerprint(in.Scope, in.CompanyID, in.TaskID, in.Kind, in.Content)
	const q = `INSERT INTO memories(scope,company_id,task_id,kind,title,content,salience,source,fingerprint,valid_from,valid_until,search_vec)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, to_tsvector('simple', $5 || ' ' || $6))
 ON CONFLICT (fingerprint) DO UPDATE SET
   salience = GREATEST(memories.salience, EXCLUDED.salience),
   valid_from  = COALESCE(EXCLUDED.valid_from,  memories.valid_from),
   valid_until = COALESCE(EXCLUDED.valid_until, memories.valid_until),
   search_vec  = EXCLUDED.search_vec,
   updated_at = now()
 RETURNING ` + memoryColsPlain + `, (xmax = 0)`
	m, created, err := scanMemoryCreated(s.db.QueryRowContext(ctx, q,
		in.Scope, co, tk, in.Kind, in.Title, in.Content, in.Salience, in.Source, fp, in.ValidFrom, in.ValidUntil))
	if err != nil {
		return nil, false, err
	}
	// 同步实体链接：正文里的 IP/域名/路径/文件/端口/CVE 进入图谱。
	if err := s.SyncEntities(ctx, m.ID, in.Content); err != nil {
		return nil, false, err
	}
	return m, created, nil
}

// scoreExpr 是 Search 与 Prune 共用的综合分：重要度 + 新鲜度(7 天衰减完) +
// 被召回次数(记忆强化，封顶 20 防独大) + 时间感知（当前有效的 +0.5，mem0
// temporal reasoning：现在能用的结论优先于历史快照）。关键词命中与全文相关度
// 是另外两个加权项，只在 Search 里额外加，因为它们依赖查询词。alias 是查询里的
// 表别名（Search 用 base，Prune 用 m）。
func scoreExpr(alias string) string {
	return fmt.Sprintf(`GREATEST(%s.salience, 0) * 2.0
    + GREATEST(1.0 - EXTRACT(EPOCH FROM (now() - COALESCE(%s.last_used_at, %s.updated_at))) / 86400.0, 0.0)
    + LEAST(%s.hit_count, 20) * 0.05
    + CASE WHEN (%s.valid_until IS NULL OR %s.valid_until > now())
             AND (%s.valid_from IS NULL OR %s.valid_from <= now())
            THEN 0.5 ELSE 0 END`,
		alias, alias, alias, alias, alias, alias, alias, alias)
}

// Search 在可见范围内按多信号融合打分召回 top-N（mem0 multi-signal retrieval）：
//
//   - matched   关键词命中计数（ILIKE，逐词）——对中文结论有效
//   - tscore    PG 全文相关度 ts_rank（'simple' 配置）——对英文/技术词（域名、路径、
//     CVE、文件名）有效；两者互补，中文靠 ILIKE、技术特征靠全文
//   - 综合分    重要度 + 新鲜度 + 被召回强化 + 时间感知（见 scoreExpr）
//
// 默认只召回当前有效的记忆（valid_until 未过期），过期结论不打扰 agent。
func (s *MemoryStore) Search(ctx context.Context, q MemorySearch) ([]*Memory, error) {
	if q.Limit <= 0 {
		q.Limit = 8
	}
	if q.Limit > 50 {
		q.Limit = 50
	}
	terms := searchTerms(q.Query)
	var co, tk *int64
	if q.CompanyID > 0 {
		co = &q.CompanyID
	}
	if q.TaskID > 0 {
		tk = &q.TaskID
	}
	where, argN := scopeWhere(co, tk, 1)
	// 实体过滤（按目标聚合）：空名 = 不过滤。
	var entityWhere string
	if strings.TrimSpace(q.Entity) != "" {
		entityWhere, _, argN = entityVisibleWhere(q.Entity, argN)
	}
	// 时间过滤：默认只召回当前有效。
	timeFilter := ""
	if !q.IncludeExpired {
		timeFilter = " AND (m.valid_until IS NULL OR m.valid_until > now())"
	}
	termArg := argN // $N：关键词数组
	queryArg := argN + 1
	limitArg := argN + 2
	qs := fmt.Sprintf(`
WITH base AS (
  SELECT m.*,
    CASE WHEN $%d::text[] IS NULL THEN 0 ELSE
      (SELECT count(*) FROM unnest($%d::text[]) t(term)
       WHERE (m.title || ' ' || m.content) ILIKE ('%%' || t.term || '%%'))
    END AS matched,
    COALESCE(ts_rank(m.search_vec, plainto_tsquery('simple', $%d)), 0) AS tscore
  FROM memories m
  WHERE m.status='active' AND %s%s%s
)
SELECT %s, matched * 2.0 + tscore * 3.0 + (%s) AS score
FROM base
ORDER BY score DESC, matched DESC, tscore DESC, base.updated_at DESC
LIMIT $%d`, termArg, termArg, queryArg, where, timeFilter, entityWhere, memoryColsPlain, scoreExpr("base"), limitArg)
	args := []any{co, tk}
	if strings.TrimSpace(q.Entity) != "" {
		args = append(args, strings.TrimSpace(q.Entity))
	}
	args = append(args, terms, q.Query, q.Limit)
	rows, err := s.db.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Memory, 0, q.Limit)
	for rows.Next() {
		m, err := scanMemory(rows, true)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// searchTerms 把查询串切成关键词：按非字母数字切分，去重，最多 8 个、
// 每个至少 2 个字符。中文无空格故按整串处理——单个长关键词，ILIKE 仍能按
// 子串命中；够用，且不引入分词扩展依赖。
func searchTerms(query string) []string {
	raw := strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r >= 0x4e00)
	})
	seen := map[string]bool{}
	out := []string{}
	for _, s := range raw {
		if len([]rune(s)) < 2 || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// List 按条件列出记忆（管理界面用），返回条目与总数。
func (s *MemoryStore) List(ctx context.Context, f MemoryFilter) ([]*Memory, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	conds := []string{"1=1"}
	args := []any{}
	add := func(placeholder string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(placeholder, len(args)))
	}
	if f.Scope != "" {
		add("m.scope=$%d", f.Scope)
	}
	if f.Kind != "" {
		add("m.kind=$%d", f.Kind)
	}
	if f.Status != "" {
		add("m.status=$%d", f.Status)
	}
	if f.CompanyID > 0 {
		add("m.company_id=$%d", f.CompanyID)
	}
	if f.TaskID > 0 {
		add("m.task_id=$%d", f.TaskID)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		add("(m.title || ' ' || m.content) ILIKE $%d", "%"+strings.ToLower(q)+"%")
	}
	if f.Entity != "" {
		add(`m.id IN (SELECT l.memory_id FROM memory_entity_links l
		     JOIN memory_entities e ON e.id = l.entity_id WHERE e.name = $%d)`, f.Entity)
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM memories m WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.Limit, f.Offset)
	qs := `SELECT ` + memoryCols + ` FROM memories m WHERE ` + where +
		` ORDER BY m.updated_at DESC LIMIT $` + itoa64(len(args)-1) + ` OFFSET $` + itoa64(len(args))
	rows, err := s.db.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Memory, 0, f.Limit)
	for rows.Next() {
		m, err := scanMemory(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// itoa64 把下标转成 SQL 占位符序号（占位符只能拼字符串，不能拼 int）。
func itoa64(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Get 按 id 取一条记忆。
func (s *MemoryStore) Get(ctx context.Context, id int64) (*Memory, error) {
	if id <= 0 {
		return nil, ErrMemoryNotFound
	}
	m, err := scanMemory(s.db.QueryRowContext(ctx, `SELECT `+memoryCols+` FROM memories m WHERE m.id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMemoryNotFound
	}
	return m, err
}

// Update 按 id 局部更新；未设的字段保持原值。正文变化时重算 fingerprint，
// 并顺手删掉 fingerprint 撞上的其它行（编辑即合并重复），避免同事实留两条。
func (s *MemoryStore) Update(ctx context.Context, id int64, p MemoryPatch) (*Memory, error) {
	cur, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Kind != "" && !memoryKinds[strings.ToLower(p.Kind)] {
		return nil, fmt.Errorf("%w: %q", ErrMemoryBadKind, p.Kind)
	}
	if p.Status != "" && !memoryStatuses[strings.ToLower(p.Status)] {
		return nil, fmt.Errorf("%w: %q", ErrMemoryBadStatus, p.Status)
	}
	content := cur.Content
	if p.Content != "" {
		if strings.TrimSpace(p.Content) == "" {
			return nil, ErrMemoryEmpty
		}
		if n := utf8.RuneCountInString(p.Content); n > MemoryContentMax {
			p.Content = string([]rune(strings.TrimSpace(p.Content))[:MemoryContentMax]) + "…"
		}
		content = strings.TrimSpace(p.Content)
	}
	sets, args := []string{}, []any{}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, col+"=$"+itoa64(len(args)))
	}
	if p.Title != "" {
		t := strings.TrimSpace(p.Title)
		if n := utf8.RuneCountInString(t); n > MemoryTitleMax {
			t = string([]rune(t)[:MemoryTitleMax])
		}
		add("m.title", t)
	}
	if content != cur.Content {
		add("m.content", content)
	}
	if p.Kind != "" {
		add("m.kind", strings.ToLower(p.Kind))
	}
	if p.Status != "" {
		add("m.status", strings.ToLower(p.Status))
	}
	if p.Salience != nil {
		v := *p.Salience
		if v < 0 {
			v = 0
		}
		if v > 1 {
			v = 1
		}
		add("m.salience", v)
	}
	if p.ValidFrom != nil {
		add("m.valid_from", *p.ValidFrom)
	}
	if p.ValidUntil != nil {
		add("m.valid_until", *p.ValidUntil)
	}
	if len(sets) == 0 {
		return cur, nil
	}
	// 正文或类型变了 → 指纹跟着变（类型参与指纹计算）。
	if p.Content != "" || p.Kind != "" {
		add("m.fingerprint", memoryFingerprint(cur.Scope, valInt64(cur.CompanyID), valInt64(cur.TaskID), strings.ToLower(orDefault(p.Kind, cur.Kind)), content))
	}
	args = append(args, id)
	// PostgreSQL 的 UPDATE SET 不接受表别名前缀（m.title=... 会 42P01），
	// 这里剥掉 m. 前缀，WHERE/RETURNING 也不用别名。
	setsSQL := strings.ReplaceAll(strings.Join(sets, ", "), "m.", "")
	q := `UPDATE memories SET ` + setsSQL + `, updated_at=now()
 WHERE id=$` + itoa64(len(args)) + `
 RETURNING ` + memoryColsPlain
	m, err := scanMemory(s.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMemoryNotFound
	}
	if err != nil {
		return nil, err
	}
	// 指纹变化后，同指纹的旧行就是重复条目，删掉（本行已持有最新内容）。
	if content != cur.Content {
		fp := memoryFingerprint(cur.Scope, valInt64(cur.CompanyID), valInt64(cur.TaskID), strings.ToLower(orDefault(p.Kind, cur.Kind)), content)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM memories WHERE fingerprint=$1 AND id <> $2`, fp, id)
	}
	// 正文或标题变了 → 重算全文检索向量并同步实体链接。
	if content != cur.Content || p.Title != "" {
		_, _ = s.db.ExecContext(ctx, `
UPDATE memories SET search_vec = to_tsvector('simple', title || ' ' || content) WHERE id=$1`, id)
		_ = s.SyncEntities(ctx, id, m.Content)
	}
	return m, nil
}

func valInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Delete 删除一条记忆；返回是否真的删了。
func (s *MemoryStore) Delete(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM memories WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ClearAll 清空整个记忆库：记忆本体 + 实体关联 + 实体 + Obsidian 导入追踪。
//
// 顺序很重要：先删 entity_links（引用 memories 与 entities），再删 memories，
// 再删失去引用的 entities，最后清 obsidian_notes 追踪——否则下次 sync 会因
// hash 未变而跳过、抢救不回记忆。整段放在一个事务里，避免中途失败留下半清状态。
// vault 设置本身不动：用户可能仍想保留路径、日后手动重新导入。
func (s *MemoryStore) ClearAll(ctx context.Context) (map[string]int64, error) {
	counts := map[string]int64{"memories": 0, "entity_links": 0, "entities": 0, "obsidian_notes": 0}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return counts, err
	}
	defer func() { _ = tx.Rollback() }()

	steps := []struct {
		key string
		sql string
	}{
		{"entity_links", `DELETE FROM memory_entity_links`},
		{"memories", `DELETE FROM memories`},
		{"entities", `DELETE FROM memory_entities`},
		{"obsidian_notes", `DELETE FROM obsidian_notes`},
	}
	for _, st := range steps {
		res, e := tx.ExecContext(ctx, st.sql)
		if e != nil {
			return counts, e
		}
		counts[st.key], _ = res.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return counts, err
	}
	return counts, nil
}

// Touch 记录一次召回命中：hit_count + 1、last_used_at = now()。
// 这是记忆的「强化信号」——被反复用到的记忆会在打分里排到前面。
func (s *MemoryStore) Touch(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE memories SET hit_count = hit_count + 1, last_used_at = now()
WHERE id = ANY($1::bigint[])`, toInt64Array(ids))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Prune 把某作用域的记忆数压回上限以内：超出时按综合分从低到高淘汰最弱的。
// 归档条（status='archived'）不参与计数、永不被淘汰。
func (s *MemoryStore) Prune(ctx context.Context, scope string, companyID, taskID int64) (int64, error) {
	var co, tk *int64
	if companyID > 0 {
		co = &companyID
	}
	if taskID > 0 {
		tk = &taskID
	}
	where, argN := scopeWhere(co, tk, 1)
	offsetArg := argN
	qs := `DELETE FROM memories m WHERE m.id IN (
  SELECT m.id FROM memories m
  WHERE m.status='active' AND ` + where + `
  ORDER BY (` + scoreExpr("m") + `) DESC, m.id DESC
  OFFSET $` + itoa64(offsetArg) + `)`
	res, err := s.db.ExecContext(ctx, qs, co, tk, memoryCapForScope(scope))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func memoryCapForScope(scope string) int {
	switch scope {
	case MemoryScopeCompany:
		return MemoryCapCompany
	case MemoryScopeTask:
		return MemoryCapTask
	default:
		return MemoryCapGlobal
	}
}

// Stats 返回 scope × kind 的分布统计（管理界面概览用）。
func (s *MemoryStore) Stats(ctx context.Context) ([]MemoryStat, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT scope, kind, count(*) FROM memories GROUP BY scope, kind ORDER BY scope, kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MemoryStat{}
	for rows.Next() {
		var st MemoryStat
		if err := rows.Scan(&st.Scope, &st.Kind, &st.Count); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// CompanyIDsForTask 返回一个任务关联企业的全部 id。task 级记忆的检索需要它
// 先解析出企业上下文，agent 才能看见 company 级记忆。
func (s *MemoryStore) CompanyIDsForTask(ctx context.Context, taskID int64) ([]int64, error) {
	if taskID <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT company_id FROM task_scope WHERE task_id=$1 AND company_id IS NOT NULL`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// toInt64Array 把 []int64 转成 Postgres BIGINT[] 的字面量。
func toInt64Array(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = itoa64(int(id))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
