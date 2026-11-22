package guard

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/intercept"
)

// newTestInterceptor builds a DB-backed interceptor, skipping when unavailable.
func newTestInterceptor(t *testing.T) *intercept.Interceptor {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN not set — skipping DB-backed guard test")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return intercept.New(d)
}

// 任务声明 deny 约束时，工具调用必须走「人工审批」分流；在 ctx 已取消
// （任务停止）的边界上应直接 block，而不是放行、也不是留下 pending 记录。
// 没有 deny 约束时保持原行为（不介入）。
func TestDenyConstraintForcesApprovalPath(t *testing.T) {
	ic := newTestInterceptor(t)
	input, _ := json.Marshal(map[string]string{"command": "ls -la"})

	// 有 deny 约束 + 已取消 ctx → block（说明走了 ask 分流而非放行）。
	gWith := NewWithInterceptor(ic)
	gWith.SetDenyConstraintCheck(func() bool { return true })
	blocked, _, _ := gWith.Hooks().PreToolUse(canceledCtx(), "Bash", input)
	if !blocked {
		t.Fatal("deny constraint present: cancelled ctx must block the call (approval path)")
	}

	// 无 deny 约束 + 同样已取消 ctx → 放行（原规则路径不处理取消）。
	gWithout := NewWithInterceptor(ic)
	blocked, _, _ = gWithout.Hooks().PreToolUse(canceledCtx(), "Bash", input)
	if blocked {
		t.Fatal("no deny constraint: call must pass through (previous behavior)")
	}
}

func TestDenyConstraintCheckIsLive(t *testing.T) {
	ic := newTestInterceptor(t)
	flag := false
	g := NewWithInterceptor(ic)
	g.SetDenyConstraintCheck(func() bool { return flag })
	input, _ := json.Marshal(map[string]string{"command": "ls"})

	// 初次无约束 → 放行。
	if blocked, _, _ := g.Hooks().PreToolUse(canceledCtx(), "Bash", input); blocked {
		t.Fatal("no constraint yet: must pass through")
	}
	// 运行时新增约束后，下一次调用立即生效（检查器每次现读，不缓存）。
	flag = true
	if blocked, _, _ := g.Hooks().PreToolUse(canceledCtx(), "Bash", input); !blocked {
		t.Fatal("constraint added at runtime: next call must take approval path")
	}
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
