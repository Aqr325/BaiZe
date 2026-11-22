// obsidian.go — 把本地 Obsidian 知识库增量同步进 memories 表。
//
// 流程（每篇 .md 笔记）：
//  1. 查 obsidian_notes 追踪表看该笔记上次导入的哈希。
//  2. 哈希未变 -> 跳过（增量：不重复导入）。
//  3. 哈希变了/首次 -> 落库为一条记忆：已有则 Update（保留作用域），
//     首次则 Put（幂等指纹）。source = "obsidian:<vault>"。
//  4. 重建实体链接：技术实体 + wikilink 目标（kind=note）。
//  5. 更新追踪表。
//
// 全部离线：只读 vault 目录 + 内嵌 PG，不依赖 Python 运行时 / Obsidian 应用 /
// 外部向量库。同步是幂等 + 增量的，可反复触发。
package db

import (
	"context"
	"errors"
	"strings"

	"github.com/Autumn-27/baize/obsidian"
)

// ErrObsidianVault 表示 vault 路径为空。
var ErrObsidianVault = errors.New("obsidian vault path is required")

// ObsidianSyncOpts 是一次同步的输入。
type ObsidianSyncOpts struct {
	// Vault 是本地 Obsidian 知识库目录（绝对路径）。
	Vault string
	// Scope 是无 frontmatter 作用域时笔记的默认记忆作用域（global/company/task）。
	// 笔记 frontmatter 里写 scope 则覆盖。
	Scope string
	// Limit 单次同步的笔记条数上限（0 = 不设限）。批量导入防止一次扫几千篇。
	Limit int
}

// ObsidianSyncResult 是一次同步的结果统计。
type ObsidianSyncResult struct {
	Scanned  int      `json:"scanned"`
	Imported int      `json:"imported"` // 新建记忆
	Updated  int      `json:"updated"`  // 内容变化后更新
	Skipped  int      `json:"skipped"`  // 哈希未变，跳过
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// SyncObsidian 扫描 vault 并把笔记增量同步成记忆。可反复调用（幂等 + 增量）。
func (s *MemoryStore) SyncObsidian(ctx context.Context, opts ObsidianSyncOpts) (*ObsidianSyncResult, error) {
	res := &ObsidianSyncResult{}
	if strings.TrimSpace(opts.Vault) == "" {
		return res, ErrObsidianVault
	}
	notes, err := obsidian.Scan(opts.Vault)
	if err != nil {
		return res, err
	}
	res.Scanned = len(notes)
	for i, n := range notes {
		if opts.Limit > 0 && i >= opts.Limit {
			break
		}
		if err := s.syncOneNote(ctx, opts, n, res); err != nil {
			res.Failed++
			if len(res.Errors) < 20 {
				res.Errors = append(res.Errors, n.RelPath+": "+err.Error())
			}
		}
	}
	return res, nil
}

// syncOneNote 处理单篇笔记的增量导入。
func (s *MemoryStore) syncOneNote(ctx context.Context, opts ObsidianSyncOpts, n *obsidian.Note, res *ObsidianSyncResult) error {
	var oldHash string
	var memID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT note_hash, COALESCE(memory_id, 0) FROM obsidian_notes WHERE vault=$1 AND rel_path=$2`,
		opts.Vault, n.RelPath).Scan(&oldHash, &memID)
	if err == nil && oldHash == n.Hash {
		res.Skipped++
		return nil
	}

	scope := obsidian.NoteScope(n.Meta, opts.Scope)
	kind := obsidian.NoteKind(n.Meta, n.Tags)
	salience := obsidian.NoteSalience(n.Meta)
	source := obsidian.SourcePrefix + opts.Vault

	var m *Memory
	if memID > 0 {
		// 已导入过：内容变了，更新（保留原作用域，frontmatter 改 scope 需手动）。
		m, err = s.Update(ctx, memID, MemoryPatch{
			Title: n.Title, Kind: kind, Content: n.Body, Salience: &salience,
		})
		if err != nil {
			return err
		}
		res.Updated++
	} else {
		var created bool
		m, created, err = s.Put(ctx, MemoryInput{
			Scope: scope, Kind: kind, Title: n.Title, Content: n.Body,
			Salience: salience, Source: source,
		})
		if err != nil {
			return err
		}
		if created {
			res.Imported++
		} else {
			res.Updated++
		}
	}

	// 重建实体链接：技术实体 + wikilink 目标（kind=note）。
	if err := s.SyncEntitiesWithLinks(ctx, m.ID, n.Body, n.Links); err != nil {
		return err
	}

	// 更新追踪表。
	_, err = s.db.ExecContext(ctx, `
INSERT INTO obsidian_notes(vault, rel_path, note_hash, memory_id)
VALUES($1, $2, $3, $4)
ON CONFLICT (vault, rel_path) DO UPDATE SET
  note_hash = EXCLUDED.note_hash, memory_id = EXCLUDED.memory_id, updated_at = now()`,
		opts.Vault, n.RelPath, n.Hash, m.ID)
	return err
}

// ObsidianStats 是知识库同步状态（status 端点用）。
type ObsidianStats struct {
	Vault    string `json:"vault"`
	VaultSet bool   `json:"vault_set"`
	Notes    int    `json:"notes"`     // 追踪表里的笔记数
	Imported int    `json:"imported"`  // 关联了记忆的笔记数
	LastSync string `json:"last_sync"` // 最近一次 updated_at（空串 = 从未同步）
}

// ObsidianStatus 查询当前 vault 的同步状态。
func (s *MemoryStore) ObsidianStatus(ctx context.Context, vault string) (*ObsidianStats, error) {
	st := &ObsidianStats{Vault: vault, VaultSet: strings.TrimSpace(vault) != ""}
	if !st.VaultSet {
		return st, nil
	}
	var total, linked int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*), count(memory_id) FROM obsidian_notes WHERE vault=$1`, vault).
		Scan(&total, &linked); err != nil {
		return st, err
	}
	st.Notes, st.Imported = total, linked
	var last *string
	if err := s.db.QueryRowContext(ctx,
		`SELECT max(updated_at)::text FROM obsidian_notes WHERE vault=$1`, vault).Scan(&last); err != nil {
		return st, err
	}
	if last != nil {
		st.LastSync = *last
	}
	return st, nil
}
