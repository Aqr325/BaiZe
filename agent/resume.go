package agent

import (
	"log"
	"strings"
)

// resumeSession 从 transcript 恢复历史对话，并区分"首次运行没有文件"与
// "文件存在但损坏/读取失败"。早期三处调用都是 `_ = s.Resume(...)`，转录
// 损坏时静默按新会话启动，worker 续跑会重复已完成的动作且无任何线索可查。
//
// norma 的 Resume 不暴露带类型的错误，这里按错误文本做保守分类：只有明确
// 表示"不存在/没有记录"的才静默，其余一律记日志。宁可多记一条无害日志，
// 也不要在转录损坏时静默丢上下文。
func resumeSession(s interface{ Resume(string) error }, sessionID, where string) {
	if s == nil || sessionID == "" {
		return
	}
	err := s.Resume(sessionID)
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	for _, benign := range []string{"not exist", "no such file", "not found", "no transcript", "empty"} {
		if strings.Contains(msg, benign) {
			return
		}
	}
	log.Printf("[%s] session %s transcript resume failed (continuing fresh): %v", where, sessionID, err)
}
