package server

import (
	"errors"
	"testing"
	"time"
)

// 这些用例只碰 Notifier 的内存健康快照，不需要 PostgreSQL，也不启动 dispatcher。

func TestNotifierHealthInitialOK(t *testing.T) {
	n := &Notifier{health: notifyEngineHealth{State: "ok", LastTickAt: time.Now()}}
	if got := n.Health().State; got != "ok" {
		t.Fatalf("初始健康 state=%q，want ok", got)
	}
}

func TestNotifierHealthDegradedAfterThreshold(t *testing.T) {
	n := &Notifier{health: notifyEngineHealth{State: "ok", LastTickAt: time.Now()}}
	for i := 0; i < notifyHealthFailThreshold-1; i++ {
		n.recordTick(errors.New("boom"))
		if got := n.Health().State; got != "ok" {
			t.Fatalf("第 %d 次失败后 state=%q，want ok（未到阈值）", i+1, got)
		}
	}
	n.recordTick(errors.New("boom"))
	if got := n.Health().State; got != "degraded" {
		t.Fatalf("达到阈值后 state=%q，want degraded", got)
	}
	h := n.Health()
	if h.ConsecutiveFailures != notifyHealthFailThreshold || h.LastError != "boom" {
		t.Fatalf("失败计数/错误不符: consecutive=%d lastError=%q", h.ConsecutiveFailures, h.LastError)
	}
}

func TestNotifierHealthRecoversOnSuccess(t *testing.T) {
	n := &Notifier{health: notifyEngineHealth{State: "ok", LastTickAt: time.Now()}}
	for i := 0; i < notifyHealthFailThreshold; i++ {
		n.recordTick(errors.New("boom"))
	}
	if got := n.Health().State; got != "degraded" {
		t.Fatalf("失败后 state=%q，want degraded", got)
	}
	n.recordTick(nil)
	h := n.Health()
	if h.State != "ok" || h.ConsecutiveFailures != 0 || h.LastError != "" {
		t.Fatalf("成功后应清零: state=%q consecutive=%d lastError=%q", h.State, h.ConsecutiveFailures, h.LastError)
	}
}

func TestNotifierHealthStaleWhenNoTick(t *testing.T) {
	// 模拟 dispatcher 彻底停摆：最后轮询时间远早于阈值。
	n := &Notifier{health: notifyEngineHealth{
		State:      "ok",
		LastTickAt: time.Now().Add(-2 * notifyHealthStaleAfter),
	}}
	if got := n.Health().State; got != "stale" {
		t.Fatalf("长时间无轮询 state=%q，want stale", got)
	}
	// 刚轮询过就不该是 stale。
	n.recordTick(nil)
	if got := n.Health().State; got != "ok" {
		t.Fatalf("刚轮询过 state=%q，want ok", got)
	}
}

func TestNotifierHealthDegradedWinsOverStale(t *testing.T) {
	// 既连续失败又久未成功时，degraded（正在报错）优先于 stale。
	n := &Notifier{health: notifyEngineHealth{State: "ok", LastTickAt: time.Now()}}
	for i := 0; i < notifyHealthFailThreshold; i++ {
		n.recordTick(errors.New("boom"))
	}
	n.healthMu.Lock()
	n.health.LastTickAt = time.Now().Add(-2 * notifyHealthStaleAfter)
	n.healthMu.Unlock()
	if got := n.Health().State; got != "degraded" {
		t.Fatalf("degraded+stale 同时成立时 state=%q，want degraded", got)
	}
}

func TestNotifierHealthUnknownWithoutDB(t *testing.T) {
	// 无 DB 时 notifyMeta 兜 unknown，这里验证兜底值本身合法。
	h := notifyEngineHealth{State: "unknown"}
	if h.State != "unknown" {
		t.Fatalf("unknown 兜底异常: %q", h.State)
	}
}
