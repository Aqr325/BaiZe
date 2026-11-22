package db

import (
	"fmt"
	"testing"
	"time"
)

// 这些用例验证 api_token_tasks 的幂等不变量：同一 token + 非空气
// 只能记录一个 task。需要真实 PostgreSQL（测试库），无 DB 时跳过。

func idempotencyToken(t *testing.T) (d *DB, tokenID int64, cleanup func()) {
	t.Helper()
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	name := fmt.Sprintf("idem-%d", time.Now().UnixNano())
	in, err := NormalizeAPITokenInput(APITokenInput{Name: name, Scopes: []string{APIScopeTaskCreate}})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := d.CreateAPIToken(in)
	if err != nil {
		t.Fatal(err)
	}
	return d, tok.ID, func() {
		_, _ = d.Exec(`DELETE FROM api_token_tasks WHERE token_id=$1`, tok.ID)
		_ = d.DeleteAPIToken(tok.ID)
		d.Close()
	}
}

func TestAPITokenTaskEventIdempotent(t *testing.T) {
	d, tokenID, cleanup := idempotencyToken(t)
	defer cleanup()

	eventID := "evt-" + fmt.Sprint(time.Now().UnixNano())
	// 首次记录：inserted=true，查重命中 task 111。
	inserted, err := d.RecordAPITokenTaskEvent(tokenID, 111, eventID)
	if err != nil || !inserted {
		t.Fatalf("first record: inserted=%v err=%v", inserted, err)
	}
	got, found, err := d.APITokenTaskByEvent(tokenID, eventID)
	if err != nil || !found || got != 111 {
		t.Fatalf("lookup after first: got=%d found=%v err=%v", got, found, err)
	}

	// 重放：同 event 不同 task，唯一索引应挡住，inserted=false。
	inserted, err = d.RecordAPITokenTaskEvent(tokenID, 222, eventID)
	if err != nil || inserted {
		t.Fatalf("replay record: inserted=%v err=%v (want false, nil)", inserted, err)
	}
	// 查重仍返回最初的 task。
	got, found, err = d.APITokenTaskByEvent(tokenID, eventID)
	if err != nil || !found || got != 111 {
		t.Fatalf("lookup after replay: got=%d found=%v err=%v (want 111)", got, found, err)
	}
	// 库里该 event 只有一行。
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM api_token_tasks WHERE token_id=$1 AND event_id=$2`, tokenID, eventID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows for event=%d, want 1", n)
	}
}

func TestAPITokenTaskEventDistinctEvents(t *testing.T) {
	d, tokenID, cleanup := idempotencyToken(t)
	defer cleanup()

	e1, e2 := "e1-"+fmt.Sprint(time.Now().UnixNano()), "e2-"+fmt.Sprint(time.Now().UnixNano())
	for i, e := range []string{e1, e2} {
		inserted, err := d.RecordAPITokenTaskEvent(tokenID, int64(300+i), e)
		if err != nil || !inserted {
			t.Fatalf("event %q: inserted=%v err=%v", e, inserted, err)
		}
	}
	if got, found, err := d.APITokenTaskByEvent(tokenID, e1); err != nil || !found || got != 300 {
		t.Fatalf("e1 lookup: got=%d found=%v err=%v", got, found, err)
	}
	if got, found, err := d.APITokenTaskByEvent(tokenID, e2); err != nil || !found || got != 301 {
		t.Fatalf("e2 lookup: got=%d found=%v err=%v", got, found, err)
	}
}

func TestAPITokenTaskByEventEmptyIDNeverMatches(t *testing.T) {
	d, tokenID, cleanup := idempotencyToken(t)
	defer cleanup()

	_ = d.RecordAPITokenTask(tokenID, 999)
	got, found, err := d.APITokenTaskByEvent(tokenID, "")
	if err != nil || found || got != 0 {
		t.Fatalf("empty event lookup: got=%d found=%v err=%v (want not found)", got, found, err)
	}
}
