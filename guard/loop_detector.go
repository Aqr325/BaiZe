package guard

import (
	"sync"
	"time"
)

// DefaultLoopWindow / DefaultLoopThreshold 是死循环检测的默认参数(§7.2):
// 同一指纹在窗口内出现 ≥threshold 次判定为循环。
const (
	DefaultLoopWindow    = 60 * time.Second
	DefaultLoopThreshold = 3
)

// LoopDetector 实现「动作指纹死循环检测」(§7.2)。
// 给每个动作算指纹 hash(目标+动作类型+关键参数),同一指纹在窗口内出现 ≥threshold 次
// 即判定为循环 → 触发降速/熔断。用于捕捉智能体失控的主要形态:不是它想做坏事,
// 是它卡住了——卡住时用几乎相同的方式反复尝试,直到把目标打挂或把额度烧完。
// now 可注入以便测试;nil 用 time.Now。
type LoopDetector struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	now       func() time.Time
	seen      map[string][]time.Time
}

// NewLoopDetector 构建检测器。window<=0 用默认,threshold<=0 用默认,now nil 用 time.Now。
func NewLoopDetector(window time.Duration, threshold int, now func() time.Time) *LoopDetector {
	if window <= 0 {
		window = DefaultLoopWindow
	}
	if threshold <= 0 {
		threshold = DefaultLoopThreshold
	}
	if now == nil {
		now = time.Now
	}
	return &LoopDetector{window: window, threshold: threshold, now: now, seen: map[string][]time.Time{}}
}

// Record 记录一次动作指纹,返回窗口内累计次数与是否触发循环。
// 窗口外旧记录顺带清理(有界)。空指纹或 nil 检测器直接忽略(返回 0,false)。
func (d *LoopDetector) Record(fp string) (int, bool) {
	if d == nil || fp == "" {
		return 0, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	cutoff := now.Add(-d.window)
	kept := d.seen[fp][:0]
	for _, t := range d.seen[fp] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	d.seen[fp] = kept
	return len(kept), len(kept) >= d.threshold
}
