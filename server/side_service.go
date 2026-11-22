package server

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/sidequestion"
)

// SideQuestions 是旁路问答（btw）的领域服务：独占运行状态与锁，Server 只做
// 装配（initSideQuestions）与 HTTP 胶水。状态原本就是收拢的（sideQuestionState），
// 但方法全挂在 *Server receiver 上、任何 Server 代码都能摸到内部字段——本次拆分
// 把纯状态操作收进本类型，Server 不再直接触碰 mu/commands/pending/latest/seen/runs。
type SideQuestions struct {
	pg *db.DB

	mu       sync.Mutex
	commands sync.Mutex // short admission / clear operations only, never inference
	pending  map[string]sidequestion.Snapshot
	latest   map[string]sidequestion.Snapshot
	seen     map[string][2]int64
	runs     map[string]sideRun
	done     chan struct{}

	outputTokens int

	// buildApproval 按审批 id 构建初始快照（深度依赖 LLM 配置与拦截详情，
	// 由 Server 注入）。仅在 snapshot() 的 ApprovalID 分支被调用。
	buildApproval func(ctx context.Context, p sidequestion.Parent) (*sidequestion.Snapshot, error)
}

type sideRun struct {
	key    string
	parent sidequestion.Parent
	cancel context.CancelFunc
	done   chan struct{}
}

// newSideQuestions 构造服务并读取环境覆盖。不启动 flush 循环（见 flushLoop）。
func newSideQuestions(pg *db.DB) *SideQuestions {
	sq := &SideQuestions{
		pg:      pg,
		pending: map[string]sidequestion.Snapshot{},
		latest:  map[string]sidequestion.Snapshot{},
		seen:    map[string][2]int64{},
		runs:    map[string]sideRun{},
		done:    make(chan struct{}),
	}
	if n, err := strconv.Atoi(os.Getenv("ARTEX_BTW_MAX_OUTPUT_TOKENS")); err == nil && n >= 256 && n <= 32768 {
		sq.outputTokens = n
	}
	return sq
}

// close marks the service as finished without starting the flush loop
// (no-database mode).
func (sq *SideQuestions) close() {
	if sq == nil {
		return
	}
	close(sq.done)
}

// waitDone exposes the flush loop's completion for drain paths.
func (sq *SideQuestions) waitDone() <-chan struct{} {
	if sq == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return sq.done
}

// publish 接收 checkpoint publisher 的快照：内存去重后进入 latest+pending，
// 由 flush 循环落库。RunID=0 是任务上下文兜底快照的保留值，每请求重建、
// 不得进入内存或落库队列（否则会遮蔽真实的主 agent checkpoint）。
func (sq *SideQuestions) publish(snap sidequestion.Snapshot) {
	if sq == nil || snap.RunID == 0 {
		return
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	key := snap.Parent.Key()
	old, ok := sq.seen[key]
	if ok && (old[0] > snap.RunID || old[0] == snap.RunID && old[1] >= snap.Version) {
		return
	}
	sq.latest[key] = snap
	sq.seen[key] = [2]int64{snap.RunID, snap.Version}
	sq.pending[key] = snap
}

// flushLoop 每 250ms 落库一批 pending 快照，ctx 结束时冲刷余量后退出。
func (sq *SideQuestions) flushLoop(ctx context.Context) {
	defer close(sq.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			keepalive("btw-flush", sq.flush)
		case <-ctx.Done():
			keepalive("btw-flush", sq.flush)
			return
		}
	}
}

func (sq *SideQuestions) flush() {
	if sq == nil || sq.pg == nil {
		return
	}
	sq.commands.Lock()
	defer sq.commands.Unlock()
	sq.mu.Lock()
	pending := sq.pending
	sq.pending = map[string]sidequestion.Snapshot{}
	sq.mu.Unlock()
	for key, snap := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := sq.pg.SaveSideSnapshot(ctx, snap)
		cancel()
		sq.mu.Lock()
		if err == nil || errors.Is(err, db.ErrSideParentGone) {
			if cur, ok := sq.latest[key]; ok && cur.RunID == snap.RunID && cur.Version == snap.Version {
				delete(sq.latest, key)
			}
		} else if newer, ok := sq.pending[key]; !ok || newer.RunID < snap.RunID || newer.RunID == snap.RunID && newer.Version < snap.Version {
			sq.pending[key] = snap
		}
		sq.mu.Unlock()
		if err != nil && !errors.Is(err, db.ErrSideParentGone) {
			log.Printf("[btw] checkpoint persistence: %v", err)
		}
	}
}

// snapshot 返回该 parent 的当前上下文：优先内存 latest，其次持久化行，
// 审批 parent 无存量时经注入的 buildApproval 现场构建并落库。
func (sq *SideQuestions) snapshot(ctx context.Context, p sidequestion.Parent) (*sidequestion.Snapshot, error) {
	taskMain := p.TaskID > 0 && p.IntentID == 0
	sq.mu.Lock()
	snap, ok := sq.latest[p.Key()]
	sq.mu.Unlock()
	if ok && snap.RunID > 0 {
		return &snap, nil
	}
	if snap, err := sq.pg.SideSnapshot(ctx, p.Key()); err != nil || snap != nil {
		// A task fallback is deliberately ephemeral from the point of view of
		// context selection. Older versions persisted it at (0,0), but that row
		// must not freeze the task material or model identity for later requests.
		if taskMain && snap != nil && snap.RunID == 0 {
			return nil, nil
		}
		return snap, err
	}
	if p.ApprovalID > 0 {
		snap, err := sq.buildApproval(ctx, p)
		if err != nil {
			return nil, err
		}
		if err := sq.pg.SaveSideSnapshot(ctx, *snap); err != nil {
			return nil, err
		}
		return snap, nil
	}
	return nil, nil
}

func (sq *SideQuestions) cancelWhere(match func(sidequestion.Parent) bool) []<-chan struct{} {
	if sq == nil {
		return nil
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	var done []<-chan struct{}
	for _, run := range sq.runs {
		if match(run.parent) {
			run.cancel()
			done = append(done, run.done)
		}
	}
	return done
}

// drainTask 等待某任务的旁路运行全部结束并把快照冲刷落库。
// Called after the task admission barrier closes and the main loops drain.
// Wait for final answer/usage writes before taking the archive snapshot.
func (sq *SideQuestions) drainTask(ctx context.Context, taskID string) error {
	if sq == nil {
		return nil
	}
	id, _ := strconv.ParseInt(taskID, 10, 64)
	sq.commands.Lock()
	done := sq.cancelWhere(func(p sidequestion.Parent) bool { return p.TaskID == id })
	sq.commands.Unlock()
	for _, ch := range done {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sq.flush()
	// A failed flush must not silently leave the latest checkpoint out of archive.
	sq.mu.Lock()
	defer sq.mu.Unlock()
	for _, snap := range sq.pending {
		if snap.Parent.TaskID == id {
			return errors.New("旁路上下文尚未保存，请重试")
		}
	}
	return nil
}

// lockAdmission/unlockAdmission expose the short-operation barrier to the HTTP
// handler's admission sequence (deleting check, dedup, request start), which
// spans several deep Server calls and cannot be a single service method.
func (sq *SideQuestions) lockAdmission() {
	if sq == nil {
		return
	}
	sq.commands.Lock()
}

func (sq *SideQuestions) unlockAdmission() {
	if sq == nil {
		return
	}
	sq.commands.Unlock()
}

// cancelByKey cancels all running side questions whose parent key matches
// (DELETE history-clear path). Mirrors the original commands+mu lock ordering.
func (sq *SideQuestions) cancelByKey(key string) {
	if sq == nil {
		return
	}
	sq.commands.Lock()
	defer sq.commands.Unlock()
	sq.mu.Lock()
	defer sq.mu.Unlock()
	for _, run := range sq.runs {
		if run.key == key {
			run.cancel()
		}
	}
}

// admission reports whether the parent already has a running side question
// (busy) and whether the global concurrency cap is reached (full).
func (sq *SideQuestions) admission(p sidequestion.Parent) (busy, full bool) {
	if sq == nil {
		return false, false
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	full = len(sq.runs) >= 4
	for _, run := range sq.runs {
		if run.key == p.Key() {
			busy = true
		}
	}
	return busy, full
}

// registerRun records a running side question so cancellation and drain can find it.
func (sq *SideQuestions) registerRun(id, key string, p sidequestion.Parent, cancel context.CancelFunc) {
	if sq == nil {
		return
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	sq.runs[id] = sideRun{key: key, parent: p, cancel: cancel, done: make(chan struct{})}
}

// finishRun closes the run's done channel and drops it from the registry.
func (sq *SideQuestions) finishRun(id string) {
	if sq == nil {
		return
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	if run, ok := sq.runs[id]; ok {
		close(run.done)
	}
	delete(sq.runs, id)
}

// maxOutputTokens returns the configured output token cap for side answers.
func (sq *SideQuestions) maxOutputTokens() int {
	if sq == nil {
		return 0
	}
	return sq.outputTokens
}

// cancelByID cancels the running side question with the given exchange id, if any.
func (sq *SideQuestions) cancelByID(id string) {
	if sq == nil {
		return
	}
	sq.mu.Lock()
	defer sq.mu.Unlock()
	if run, ok := sq.runs[id]; ok {
		run.cancel()
	}
}

func (sq *SideQuestions) cancelWorker(taskID string, expID, iid int64) {
	if sq == nil {
		return
	}
	id, _ := strconv.ParseInt(taskID, 10, 64)
	p := sidequestion.Parent{TaskID: id, ExplorationID: expID, IntentID: iid}
	sq.commands.Lock()
	defer sq.commands.Unlock()
	sq.cancelWhere(func(parent sidequestion.Parent) bool { return parent == p })
}
