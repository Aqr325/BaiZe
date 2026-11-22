// checkpoint.go — 断点恢复（Checkpoint）支持。
//
// 借鉴 openEuler AET 的「任务快照 → 断点恢复」思路，为 enrich 的长任务
// （katana 爬虫、nuclei 全量扫描、httpx 万级指纹）提供跨重启的进度持久化：
//
//   - markRunning 在任务开始记 running（含 arg，供恢复重放）；
//   - markDone 在任务完成记 done；
//   - ResumeInterrupted 在 New 之后调用，把上次进程退出时仍在 running 的
//     任务重新入队（upsert 幂等，重放安全）；
//   - doneRecently 让「cooldown 窗口内已完成」的任务跨重启也不重跑
//     （原 cool map 是内存态，重启即丢）。
//
// 文件：BaseDir()/enrich_progress.json（随 exe 旁，分布式二进制自带）。
package enrich

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/baize/config"
)

// checkpoint lifecycle states.
const (
	ckptRunning = "running" // started, not finished → interrupted if process died
	ckptDone    = "done"    // completed
)

// ckptEntry is the journal row for one (kind,id) job.
type ckptEntry struct {
	Status string    `json:"status"`
	At     time.Time `json:"at"`
	Arg    string    `json:"arg,omitempty"` // url/host, so resume can re-enqueue exactly
}

// checkpointStore is a small disk-backed journal of enrich job progress.
type checkpointStore struct {
	mu      sync.Mutex
	path    string
	data    map[string]ckptEntry
	dirties int
}

func newCheckpointStore() *checkpointStore {
	c := &checkpointStore{
		path: filepath.Join(config.BaseDir(), "enrich_progress.json"),
		data: map[string]ckptEntry{},
	}
	c.load()
	return c
}

func (c *checkpointStore) key(kind jobKind, id int64) string {
	return string(rune(kind)) + ":" + itoa(id)
}

func (c *checkpointStore) load() {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return // no journal yet — fresh start
	}
	if err := json.Unmarshal(b, &c.data); err != nil {
		log.Printf("[enrich] 断点日志解析失败（忽略，重新开始）: %v", err)
		c.data = map[string]ckptEntry{}
		return
	}
	// Prune entries older than 24h so the journal never grows unbounded.
	cutoff := time.Now().Add(-24 * time.Hour)
	for k, e := range c.data {
		if e.At.Before(cutoff) {
			delete(c.data, k)
		}
	}
}

// save persists the journal. Callers must not hold c.mu when calling.
func (c *checkpointStore) save() {
	if c == nil || c.path == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.path, b, 0o644)
}

// markRunning records that a job started; arg is preserved so resume can replay it.
func (c *checkpointStore) markRunning(j job) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.data[c.key(j.kind, j.id)] = ckptEntry{Status: ckptRunning, At: time.Now(), Arg: j.arg}
	c.dirties++
	should := c.dirties%16 == 0
	c.mu.Unlock()
	if should {
		c.save()
	}
}

// markDone records that a job was fully processed.
func (c *checkpointStore) markDone(kind jobKind, id int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	key := c.key(kind, id)
	e := c.data[key]
	e.Status = ckptDone
	e.At = time.Now()
	c.data[key] = e
	c.dirties++
	should := c.dirties%16 == 0
	c.mu.Unlock()
	if should {
		c.save()
	}
}

// doneRecently reports whether (kind,id) completed within the cooldown window.
func (c *checkpointStore) doneRecently(kind jobKind, id int64) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[c.key(kind, id)]
	return ok && e.Status == ckptDone && time.Since(e.At) < cooldown
}

// interrupted returns jobs marked running but never completed (process died
// mid-work), for resume.
func (c *checkpointStore) interrupted() []job {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []job
	for k, e := range c.data {
		if e.Status != ckptRunning {
			continue
		}
		kind, id := parseKey(k)
		if id <= 0 {
			continue
		}
		out = append(out, job{kind: kind, id: id, arg: e.Arg})
	}
	return out
}

// parseKey splits "kind:id" back into its parts.
func parseKey(k string) (jobKind, int64) {
	if len(k) < 3 {
		return 0, 0
	}
	kind := jobKind(k[0])
	id, err := strconv.ParseInt(k[2:], 10, 64)
	if err != nil {
		return 0, 0
	}
	return kind, id
}
