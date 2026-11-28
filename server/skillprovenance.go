package server

// skillprovenance.go — ⑤ marketplace 溯源 hash 校验。
//
// 背景：skills/ 既有 git 保护，但运行时经 fsUploadSkill 安装的 skill 没有 git
// 历史；第三方 skill 也常以「vendored 拷贝」形态存在（无 .git）。为此给每个
// skill 钉一个「内容 tree-hash」+ 来源元数据，加载时重算比对：
//
//   - mismatch（tree-hash 变了）→ 判定为篡改/漂移 → 隔离（不进 reg）+ 落审计
//   - missing（不在清单）→ 无法溯源 → 仅告警（fail-open，不阻断，保持兼容）
//   - error（清单不可读/哈希失败）→ 告警（fail-open）
//
// 树哈希把 skill 目录下所有文件（相对路径排序）的逐文件 sha256 拼成规范串再
// 求一次 sha256 —— 与文件顺序/mtime 无关，任一文件增删改都会改变结果。大库
// （anthropic-cybersecurity 4533 文件）也只需一次遍历，结果仍是单条 64 位 hex。
//
// 清单位置：<skillDir>/provenance.json。初始清单由
// `go run ./cmd/skillprovenance -dir <skillDir>` 生成并提交；内容变更后需重跑
// 该命令重新钉版（这是「防投毒」的刻意摩擦：任何内容变化都要显式重钉）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const skillProvenanceVersion = 1

// skillProvenanceFileName is the manifest name inside the skill dir.
const skillProvenanceFileName = "provenance.json"

// skillProvenance pins one skill's content snapshot + source metadata.
type skillProvenance struct {
	Origin   string `json:"origin,omitempty"`
	License  string `json:"license,omitempty"`
	Pinned   string `json:"pinned,omitempty"`
	TreeHash string `json:"tree_hash"`
}

// skillProvenanceManifest is the on-disk manifest format.
type skillProvenanceManifest struct {
	Version   int                        `json:"version"`
	Generated string                     `json:"generated"`
	Skills    map[string]skillProvenance `json:"skills"`
}

func skillProvenanceManifestPath(skillDir string) string {
	return filepath.Join(skillDir, skillProvenanceFileName)
}

// SkillTreeHash computes a canonical sha256 over every file under skillDir/name.
func SkillTreeHash(skillDir, name string) (string, error) {
	root := filepath.Join(skillDir, name)
	agg := sha256.New()
	var rels []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(rels)
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		fh := sha256.Sum256(data)
		fmt.Fprintf(agg, "%s\x00%s\n", rel, hex.EncodeToString(fh[:]))
	}
	return hex.EncodeToString(agg.Sum(nil)), nil
}

func loadSkillProvenance(skillDir string) (map[string]skillProvenance, error) {
	data, err := os.ReadFile(skillProvenanceManifestPath(skillDir))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]skillProvenance{}, nil // no manifest → fail-open
		}
		return nil, err
	}
	var man skillProvenanceManifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, err
	}
	if man.Skills == nil {
		man.Skills = map[string]skillProvenance{}
	}
	return man.Skills, nil
}

func saveSkillProvenance(skillDir string, m map[string]skillProvenance) error {
	man := skillProvenanceManifest{
		Version:   skillProvenanceVersion,
		Generated: time.Now().Format(time.RFC3339),
		Skills:    m,
	}
	data, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(skillProvenanceManifestPath(skillDir), data, 0o644)
}

// provenanceStatus is the outcome of a load-time provenance check.
type provenanceStatus string

const (
	provOK       provenanceStatus = "ok"
	provMismatch provenanceStatus = "mismatch" // content changed → tamper/drift → isolate
	provMissing  provenanceStatus = "missing"  // not in manifest → warn, allow
	provError    provenanceStatus = "error"    // manifest/hash failure → warn, allow
)

type provenanceCheck struct {
	Status provenanceStatus
	Detail string
}

// CheckSkillProvenance recomputes name's tree hash and compares to the manifest.
// Only a mismatch (content changed) is treated as a security event; missing and
// error are advisory so a missing manifest never breaks an existing deployment.
func CheckSkillProvenance(skillDir, name string) provenanceCheck {
	man, err := loadSkillProvenance(skillDir)
	if err != nil {
		return provenanceCheck{provError, "provenance manifest unreadable: " + err.Error()}
	}
	want, ok := man[name]
	if !ok {
		return provenanceCheck{provMissing, "skill not in provenance manifest; origin unverifiable"}
	}
	got, err := SkillTreeHash(skillDir, name)
	if err != nil {
		return provenanceCheck{provError, "tree hash failed: " + err.Error()}
	}
	if got != want.TreeHash {
		return provenanceCheck{provMismatch,
			fmt.Sprintf("content tree hash changed: want %s got %s (tamper/drift? regen manifest to re-pin)", want.TreeHash, got)}
	}
	return provenanceCheck{provOK, "provenance verified: " + want.Origin}
}

// RecordSkillProvenance recomputes and pins name's tree hash (+metadata).
// Used after fsUploadSkill installs a runtime skill.
func RecordSkillProvenance(skillDir, name, origin, license string) error {
	th, err := SkillTreeHash(skillDir, name)
	if err != nil {
		return err
	}
	man, err := loadSkillProvenance(skillDir)
	if err != nil {
		return err
	}
	prev := man[name]
	if origin == "" {
		origin = prev.Origin
	}
	if license == "" {
		license = prev.License
	}
	man[name] = skillProvenance{
		Origin: origin, License: license,
		Pinned: time.Now().Format("2006-01-02"), TreeHash: th,
	}
	return saveSkillProvenance(skillDir, man)
}

// RegenerateSkillProvenance re-pins every skill directory under skillDir.
// originFn (optional) supplies (origin, license) per skill; if nil, existing
// metadata is preserved and new skills get empty origin.
func RegenerateSkillProvenance(skillDir string, originFn func(name string) (string, string)) (int, error) {
	entries, err := os.ReadDir(skillDir)
	if err != nil {
		return 0, err
	}
	man, err := loadSkillProvenance(skillDir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := e.Name()
		th, err := SkillTreeHash(skillDir, name)
		if err != nil {
			return count, fmt.Errorf("skill %s: %w", name, err)
		}
		prev := man[name]
		origin, license := prev.Origin, prev.License
		if originFn != nil {
			if o, l := originFn(name); o != "" || l != "" {
				origin, license = o, l
			}
		}
		man[name] = skillProvenance{
			Origin: origin, License: license,
			Pinned: time.Now().Format("2006-01-02"), TreeHash: th,
		}
		count++
	}
	if err := saveSkillProvenance(skillDir, man); err != nil {
		return count, err
	}
	return count, nil
}
