package db

import (
	"testing"
	"time"
)

// TestPruneLogsBefore 覆盖保留策略执行端：插入新旧两行，修剪只删旧的那行。
// 需要 ARTEX_PG_DSN（无库环境自动 SKIP）。
func TestPruneLogsBefore(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	oldID, err := d.InsertLog("info", "retention-test", "old row")
	if err != nil {
		t.Fatal(err)
	}
	newID, err := d.InsertLog("info", "retention-test", "new row")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec("DELETE FROM server_logs WHERE id IN ($1,$2)", oldID, newID)
	})

	// 把旧行的 created_at 改到 8 天前，保留期是 7 天。
	if _, err := d.Exec("UPDATE server_logs SET created_at = now() - interval '8 days' WHERE id = $1", oldID); err != nil {
		t.Fatal(err)
	}

	n, err := d.PruneLogsBefore(time.Now().Add(-7 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("expected at least 1 pruned row, got %d", n)
	}

	var cnt int
	if err := d.QueryRow(
		"SELECT count(*) FROM server_logs WHERE id IN ($1,$2)", oldID, newID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("expected only the new row to survive, found %d rows", cnt)
	}
	var text string
	if err := d.QueryRow(
		"SELECT text FROM server_logs WHERE id = $1", newID).Scan(&text); err != nil {
		t.Fatal(err)
	}
	if text != "new row" {
		t.Fatalf("surviving row mismatch: %q", text)
	}
}
