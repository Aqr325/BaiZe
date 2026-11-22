package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/baize/db"
)

// ---------- MCP 模板库 ----------
//
// 一组预配置的实用 MCP 服务器，用户在 MCP 页「从模板添加」里挑一个，
// 前端把模板值预填进表单（可改）后走普通保存流程。这里只提供只读清单，
// 不在安装时隐式写库——所见即所得，避免"点一下就多出个半配置的服务器"。
//
// stdio 模板的 command 固定为 cmd /c npx：Windows 上 exec.Command 直接跑
// "npx" 会命中 .cmd 包装脚本（Go 对 .bat/.cmd 要求绝对路径），cmd /c 是
// 唯一在所有 Windows 环境都稳的写法。

type mcpTemplate struct {
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Category    string            `json:"category"` // 通用 | 自检 | 内部
	Description string            `json:"description"`
	Transport   string            `json:"transport"`
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	URL         string            `json:"url,omitempty"`
	Insecure    bool              `json:"insecure,omitempty"`
	// Reminders 在前端模板卡片上展示的配置提示（如"去 MCP 服务端页生成令牌"）。
	Reminders []string `json:"reminders,omitempty"`
}

func builtinMCPTemplates() []mcpTemplate {
	return []mcpTemplate{
		{
			Key:      "filesystem",
			Name:     "filesystem",
			Category: "通用",
			Description: "本地文件读写（官方 @modelcontextprotocol/server-filesystem）。限定在一个允许目录内，" +
				"供 agent 落 PoC 脚本、证据文件和报告草稿。默认目录 D:\\artex-workspace 可改。",
			Transport: "stdio",
			Command:   "cmd",
			Args:      []string{"/c", "npx", "-y", "@modelcontextprotocol/server-filesystem", "D:\\artex-workspace"},
			Reminders: []string{"首次启动需联网拉取 npm 包；请确认允许目录存在或改成已有目录"},
		},
		{
			Key:      "memory",
			Name:     "memory",
			Category: "通用",
			Description: "知识图谱长期记忆（官方 @modelcontextprotocol/server-memory）。" +
				"把目标资产、凭据线索、历史结论存成实体-关系图，跨任务/跨会话复用。",
			Transport: "stdio",
			Command:   "cmd",
			Args:      []string{"/c", "npx", "-y", "@modelcontextprotocol/server-memory"},
			Reminders: []string{"记忆默认存 JSONL 文件，跟随工作目录；敏感信息会落盘请注意"},
		},
		{
			Key:      "sequential-thinking",
			Name:     "sequential-thinking",
			Category: "通用",
			Description: "分步推理工具（官方 @modelcontextprotocol/server-sequential-thinking）。" +
				"给 agent 一个可动态修订的思考缓冲区，适合复杂攻击链规划与多步漏斗收敛。",
			Transport: "stdio",
			Command:   "cmd",
			Args:      []string{"/c", "npx", "-y", "@modelcontextprotocol/server-sequential-thinking"},
		},
		{
			Key:      "everything",
			Name:     "everything",
			Category: "自检",
			Description: "官方自检服务器（@modelcontextprotocol/server-everything）。" +
				"包含 echo/加法/错误注入等一堆小工具，用来验证 ARTEX 的 stdio MCP 通道是否畅通，" +
				"排查「工具发现失败」时先用它对照。",
			Transport: "stdio",
			Command:   "cmd",
			Args:      []string{"/c", "npx", "-y", "@modelcontextprotocol/server-everything"},
		},
		{
			Key:      "artex-self",
			Name:     "artex-self",
			Category: "内部",
			Description: "ARTEX 自身对外暴露的 /mcp 端点（Streamable HTTP）。把 ARTEX 的内置工具" +
				"反向接回 agent 侧，或供外部 MCP 宿主（如 Claude/其他客户端）远程调用本机 ARTEX。",
			Transport: "http",
			URL:       "http://127.0.0.1:8787/mcp",
			Env:       map[string]string{"Authorization": "Bearer artex_mcp_"},
			Reminders: []string{
				"先在「系统设置 → MCP 服务端」里创建访问令牌，把完整令牌填进 Authorization 头",
				"令牌格式 artex_mcp_...，注意 Bearer 后保留一个空格",
			},
		},
	}
}

// pgMCPTemplates returns the built-in template catalog for the MCP page.
func (s *Server) pgMCPTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"templates": builtinMCPTemplates()})
}

// ---------- MCP 连接测试 ----------

// pgTestMCP dials a not-yet-saved MCP config (same payload shape as POST /api/mcp)
// and returns its tool list, so the UI can validate before persisting.
func (s *Server) pgTestMCP(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var m db.MCPServer
	if err := decode(r, &m); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateMCPConfig(&m); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 与 pgSaveMCP 的工具发现同一上限：stdio 模板首次 npx 拉包可能要几十秒。
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	cl, err := connectMCP(ctx, &m)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": humanizeMCPDialError(err).Error()})
		return
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": humanizeMCPDialError(err).Error()})
		return
	}
	type testTool struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	tools := make([]testTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, testTool{Name: t.Name(), Description: t.Description()})
	}
	log.Printf("[mcp] 连接测试 %s: ok, %d 个工具", m.Name, len(tools))
	writeJSON(w, 200, map[string]any{"ok": true, "tools": tools})
}

// validateMCPConfig checks transport-specific required fields before dialing.
func validateMCPConfig(m *db.MCPServer) error {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return errMCPField("stdio 传输缺少命令")
		}
	case "http", "sse":
		if m.URL == "" {
			return errMCPField(m.Transport + " 传输缺少 URL")
		}
	default:
		return errMCPField("未知传输方式 " + m.Transport)
	}
	return nil
}

type mcpFieldError struct{ msg string }

func (e mcpFieldError) Error() string { return e.msg }

func errMCPField(msg string) error { return mcpFieldError{msg: msg} }

// humanizeMCPDialError 把底层拨号错误翻译成用户能行动的提示。norma 的 stdio
// 客户端吞掉了子进程 stderr，"connection closed" 几乎总是「进程起了但初始化
// 握手没完成」，常见原因按命中率排序给出。
func humanizeMCPDialError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection closed"):
		return fmt.Errorf("%w（stdio 子进程启动后立即退出。常见原因：① 服务以 SYSTEM 等账户运行，命令/依赖路径对服务账户不可见——建议用绝对路径；② npx 首次拉包失败或未安装——先在用户终端跑一次确认；③ 命令不是 MCP 服务器）", err)
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "deadline"):
		return fmt.Errorf("%w（握手超时：首次 npx 拉包可能需要 1-2 分钟，重试一次；仍超时则检查网络或代理设置）", err)
	default:
		return err
	}
}
