package guard

import (
	"errors"
	"sync"
)

// ErrTierForbidden 表示 A4 禁止动作:一票否决,策略层硬阻断(§5.1)。
var ErrTierForbidden = errors.New("A4 禁止动作")

// ErrTierBudgetExhausted 表示该等级动作预算耗尽:爆炸半径预算,耗尽即停(§5.4)。
var ErrTierBudgetExhausted = errors.New("动作分级预算耗尽")

// DefaultActionBudgetA2 / DefaultActionBudgetA3 是任务默认动作额度(§5.4 经验值):
// A2 ≤ 5、A3 ≤ 1、A4 恒为 0。
const (
	DefaultActionBudgetA2 = 5
	DefaultActionBudgetA3 = 1
)

// ActionBudget 是每任务的「动作分级爆炸半径预算」(§5.4)。
// 每次任务下发分配一次性额度,由 Spend 原子扣减;耗尽即停——不因"再试一次就成功了"
// 而追加。A0/A1 不受限(只读观测/低影响探测);A4 恒为 0(禁止)。
// nil budget 表示未启用分级门禁(兼容旧行为)。
type ActionBudget struct {
	mu sync.Mutex
	a2 int // 剩余 A2 额度
	a3 int // 剩余 A3 额度
}

// NewActionBudget 构建预算。a2/a3 为非负额度(0 表示该级 0 次,即全拒);
// 负值表示关闭该级门禁(不限制),用于显式放宽。A4 恒为 0。
func NewActionBudget(a2, a3 int) *ActionBudget {
	return &ActionBudget{a2: a2, a3: a3}
}

// Spend 尝试消费一次 tier 等级动作的额度(§5.4):
//   - A4 → 恒拒(ErrTierForbidden);
//   - A3/A2 额度耗尽 → 拒(ErrTierBudgetExhausted);
//   - A0/A1 → 放行(不限)。
//
// 并发安全;nil budget(未启用)恒放行。
func (b *ActionBudget) Spend(tier ActionTier) error {
	if b == nil {
		return nil
	}
	switch tier {
	case TierA4:
		return ErrTierForbidden
	case TierA3:
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.a3 < 0 {
			return nil // 该级门禁关闭
		}
		if b.a3 <= 0 {
			return ErrTierBudgetExhausted
		}
		b.a3--
		return nil
	case TierA2:
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.a2 < 0 {
			return nil
		}
		if b.a2 <= 0 {
			return ErrTierBudgetExhausted
		}
		b.a2--
		return nil
	default: // A0 / A1
		return nil
	}
}

// Remaining 返回指定等级剩余额度(观测/测试用);未启用或非额度等级返回 0。
func (b *ActionBudget) Remaining(tier ActionTier) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch tier {
	case TierA2:
		return b.a2
	case TierA3:
		return b.a3
	}
	return 0
}
