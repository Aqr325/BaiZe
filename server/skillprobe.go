package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// skillContentProbe 是 package 级 skill 正文解析器：Guard 用它把 skill 的
// Instructions 对用户 deny 规则跑一遍（供应链安全审计 §2.1——恶意 skill 正文=
// 提示注入面，tool-call 边界看不到，需要单独一层）。
// 在 server.New 用固定的 skillDir 注册一次；从磁盘读正文，与每轮 agent 会话
// 重建的 registry 解耦，避免时序/竞态耦合。
var skillContentProbe atomic.Value // func(name string) (string, bool)

// SetSkillContentProbe 注册正文解析器（server.New 调用一次）。
func SetSkillContentProbe(fn func(string) (string, bool)) {
	if fn != nil {
		skillContentProbe.Store(fn)
	}
}

// GetSkillContentProbe 返回已注册的解析器；未注册时返回 nil。
func GetSkillContentProbe() func(string) (string, bool) {
	if v := skillContentProbe.Load(); v != nil {
		return v.(func(string) (string, bool))
	}
	return nil
}

// skillContentFromDisk 构造一个从 <dir>/<name>/SKILL.md 读正文的解析器。
// 磁盘上每个 skill 是子目录，按目录名键控；每次调用重读，磁盘改动下次生效。
func skillContentFromDisk(dir string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if dir == "" || strings.TrimSpace(name) == "" {
			return "", false
		}
		p := filepath.Join(dir, name, "SKILL.md")
		data, err := os.ReadFile(p)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
}
