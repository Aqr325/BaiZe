package server

import (
	"log"
	"time"
)

// serverLogRetention 是 server_logs 的保留期：无人值守的长期运行下，日志表
// 只进不出会无限膨胀，超过保留期的行由 pruneLogsTick 定时删除。
const serverLogRetention = 7 * 24 * time.Hour

// pruneLogsTick 每小时清理一次超过保留期的 server_logs。挂在 Scheduler 的
// 5 秒 tick 上（tick body 已有 keepalive panic 防护），pg 未配置时静默跳过。
func (s *Server) pruneLogsTick(now time.Time) {
	if s.m.pg == nil {
		return
	}
	if now.Sub(s.lastLogPrune) < time.Hour {
		return
	}
	s.lastLogPrune = now
	n, err := s.m.pg.PruneLogsBefore(now.Add(-serverLogRetention))
	if err != nil {
		log.Printf("[logs] prune: %v", err)
	} else if n > 0 {
		log.Printf("[logs] 已清理 %d 条超过 %s 的 server_logs", n, serverLogRetention)
	}
}
