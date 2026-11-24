package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func boolStr(b bool) string { return strconv.FormatBool(b) }

// 本文件实现「拦截防御配置变更审计」——对照云鼎实验室 AI 攻防挑战赛复盘的
// 判断三：自主防御本身会成为新的攻击面，必须可控、可审计。
//
// 白泽的拦截规则 / 判官配置写操作原先零审计：任意一个持有效 JWT 的登录会话
// 都能无痕地关闭判官、删除内置破坏性拦截规则、把 fail_action 降级为 allow。
// 单用户系统里角色分级价值有限（都是同一个管理员），真正缺的是「可追溯」。
//
// 实现走标准 log.Printf("[intercept-config] ...")：logSink 自动 tee 到内存环、
// SSE 与 server_logs（7 天保留），无需新增表或迁移。降级类操作标 WARN，
// 让「防御基线被削弱」在日志页一眼可见。文本用 JSON，便于事后按字段检索。

const interceptConfigTag = "intercept-config"

// interceptConfigEvent 是写进日志的一条配置变更事件。字段刻意扁平、稳定。
type interceptConfigEvent struct {
	Op      string `json:"op"`               // create_rule|update_rule|delete_rule|toggle_rule|set_tool_config|set_judge_config
	Actor   string `json:"actor"`            // 来源 IP（authClientIP，不信任 XFF）
	Target  string `json:"target,omitempty"` // rule id 或对象名
	Detail  string `json:"detail,omitempty"` // 关键新值摘要
	Degrade bool   `json:"degrade"`          // 是否削弱了安全基线
	Why     string `json:"why,omitempty"`    // 降级原因说明
}

// auditInterceptConfig 落一条配置变更审计。degrade=true 时用 WARN 级，
// 否则 INFO。JSON 序列化失败时退化为纯文本，绝不因审计失败阻断配置操作。
func auditInterceptConfig(r *http.Request, ev interceptConfigEvent) {
	ev.Actor = authClientIP(r)
	payload, err := json.Marshal(ev)
	level := "INFO"
	prefix := ""
	if ev.Degrade {
		level = "WARN"
		prefix = "[安全基线降级] "
	}
	text := prefix + string(payload)
	if err != nil {
		text = prefix + "op=" + ev.Op + " actor=" + ev.Actor + " target=" + ev.Target + " detail=" + ev.Detail
	}
	log.Printf("[%s] %s %s", interceptConfigTag, level, text)
}

// isBuiltinRule 判定是否为内置安全基线规则（含反蜜罐规则）。删除/禁用这类
// 规则属于安全降级，审计要标 WARN。
func isBuiltinRule(name string) bool {
	return strings.HasPrefix(name, "[内置")
}

// judgeDegradeReason 返回判官配置里削弱安全基线的点，空串表示无降级。
// fail_action=allow：判官解析失败/模型错误时放行；ask_timeout_action=allow：
// 人工超时未裁决时放行；enabled=false：整体关闭兜底判官。
func judgeDegradeReason(enabled bool, failAction, askTimeoutAction string) string {
	var reasons []string
	if !enabled {
		reasons = append(reasons, "判官已关闭")
	}
	if failAction == "allow" {
		reasons = append(reasons, "fail_action=allow(解析失败放行)")
	}
	if askTimeoutAction == "allow" {
		reasons = append(reasons, "ask_timeout_action=allow(审批超时放行)")
	}
	return strings.Join(reasons, "; ")
}
