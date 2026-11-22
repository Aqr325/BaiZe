package enrich

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestStore builds a checkpoint store backed by a temp file.
func newTestStore(t *testing.T) *checkpointStore {
	t.Helper()
	return &checkpointStore{
		path: filepath.Join(t.TempDir(), "enrich_progress.json"),
		data: map[string]ckptEntry{},
	}
}

func TestCheckpointLifecycle(t *testing.T) {
	c := newTestStore(t)
	j := job{kind: jobCrawl, id: 42, arg: "http://example.com"}

	if c.doneRecently(jobCrawl, 42) {
		t.Fatal("新 store 不应认为任务已完成")
	}

	c.markRunning(j)
	if got := c.interrupted(); len(got) != 1 || got[0].kind != jobCrawl || got[0].id != 42 || got[0].arg != j.arg {
		t.Fatalf("markRunning 后 interrupted 应含该任务: %+v", got)
	}

	c.markDone(jobCrawl, 42)
	if got := c.interrupted(); len(got) != 0 {
		t.Fatalf("markDone 后 interrupted 应为空: %+v", got)
	}
	if !c.doneRecently(jobCrawl, 42) {
		t.Fatal("markDone 后 doneRecently 应为 true")
	}
}

func TestCheckpointPersistence(t *testing.T) {
	c := newTestStore(t)
	c.markRunning(job{kind: jobHTTP, id: 7, arg: "http://x.test"})
	c.markDone(jobDNS, 9)
	c.save()

	// Reload from the same path — the journal must survive a "restart".
	c2 := &checkpointStore{
		path: c.path,
		data: map[string]ckptEntry{},
	}
	c2.load()

	if !c2.doneRecently(jobDNS, 9) {
		t.Fatal("重载后 jobDNS/9 应视为已完成")
	}
	got := c2.interrupted()
	if len(got) != 1 || got[0].kind != jobHTTP || got[0].id != 7 || got[0].arg != "http://x.test" {
		t.Fatalf("重载后 interrupted 应恢复 jobHTTP/7: %+v", got)
	}
}

func TestCheckpointPruneOld(t *testing.T) {
	c := newTestStore(t)
	key := c.key(jobNuclei, 5)
	c.data[key] = ckptEntry{Status: ckptDone, At: time.Now().Add(-25 * time.Hour)}
	c.save() // 落盘：包含过期条目

	// 重新加载（模拟重启）→ load 应剪枝 >24h 的过期条目。
	c2 := &checkpointStore{
		path: c.path,
		data: map[string]ckptEntry{},
	}
	c2.load()
	if _, ok := c2.data[key]; ok {
		t.Fatal("超过 24h 的条目应被剪枝")
	}
}

func TestParseKey(t *testing.T) {
	kind, id := parseKey(string(rune(jobCrawl)) + ":123")
	if kind != jobCrawl || id != 123 {
		t.Fatalf("parseKey 解析错误: kind=%d id=%d", kind, id)
	}
	if _, id := parseKey("bad"); id != 0 {
		t.Fatalf("非法 key 应返回 id=0")
	}
}

func TestCheckpointNilSafety(t *testing.T) {
	var c *checkpointStore
	c.markRunning(job{})
	c.markDone(jobDNS, 1)
	c.save()
	if c.doneRecently(jobDNS, 1) {
		t.Fatal("nil store 应返回 false")
	}
	if got := c.interrupted(); got != nil {
		t.Fatal("nil store 应返回 nil")
	}
}
