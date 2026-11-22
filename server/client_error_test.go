package server

import (
	"strings"
	"testing"
)

// TestSanitizeClientErrorMasksSecrets verifies that sensitive internals never
// reach the browser: proxy/DSN credentials, host paths, and SQL/pgx error detail.
func TestSanitizeClientErrorMasksSecrets(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		forbid []string // substrings that must NOT survive
	}{
		{
			name:   "proxy url credentials",
			in:     `Post "http://admin:s3cr3t@10.0.0.5:8080/probe": dial tcp: connection refused`,
			forbid: []string{"admin:s3cr3t", "10.0.0.5"},
		},
		{
			name:   "postgres dsn credentials",
			in:     `failed to connect: postgres://artex:pw123@db.internal:5432/artex?sslmode=disable`,
			forbid: []string{"artex:pw123", "db.internal"},
		},
		{
			name:   "unix host path",
			in:     `open /etc/ssl/private/key.pem: permission denied`,
			forbid: []string{"/etc/ssl/private/key.pem"},
		},
		{
			name:   "windows host path",
			in:     `open D:\workbuddy workspace\ARTEX\data\keys\jwt.key: access denied`,
			forbid: []string{`D:\workbuddy`},
		},
		{
			name:   "pgx sqlstate",
			in:     `ERROR: relation "secrets" does not exist (SQLSTATE 42P01)`,
			forbid: []string{"secrets", "SQLSTATE", "42P01"},
		},
		{
			name:   "constraint leak",
			in:     `ERROR: duplicate key value violates unique constraint "api_keys_pkey" (SQLSTATE 23505)`,
			forbid: []string{"api_keys_pkey", "SQLSTATE", "23505"},
		},
		{
			name:   "syntax error leak",
			in:     `ERROR: syntax error at or near "SELECT password FROM users" (SQLSTATE 42601)`,
			forbid: []string{"SELECT password", "SQLSTATE"},
		},
		{
			name:   "auth failure leak",
			in:     `password authentication failed for user "artex_svc"`,
			forbid: []string{"artex_svc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeClientError(tc.in)
			for _, bad := range tc.forbid {
				if strings.Contains(got, bad) {
					t.Errorf("sanitizeClientError(%q) still contains %q: %q", tc.in, bad, got)
				}
			}
		})
	}
}

// TestSanitizeClientErrorPreservesBusinessErrors is the critical complement:
// validation messages and i18n keys are plain text that the frontend displays
// (and in one case branches on). They must pass through byte-for-byte.
func TestSanitizeClientErrorPreservesBusinessErrors(t *testing.T) {
	cases := []string{
		"当前会话已有旁路问题正在回答",                        // db.ErrSideBusy
		"Jev System One 配置仅可用于拦截判定模型，不能用于对话或任务", // db.ErrJevProfileJudgeOnly
		"密码长度至少 8 位",
		"taskFiles.failed", // i18n key
		"streaming unsupported",
		"saved provider is unavailable",
		"尚未配置 LLM：请到 系统 → LLM 配置 添加一个配置",
		"漏洞不存在",
		"invalid api token",
		"",
	}
	for _, in := range cases {
		if got := sanitizeClientError(in); got != in {
			t.Errorf("sanitizeClientError changed business message: in=%q got=%q", in, got)
		}
	}
}

// TestSanitizeClientErrorPathKeepsContext checks that path masking is surgical:
// the surrounding human-readable context survives so the user still understands
// which operation failed.
func TestSanitizeClientErrorPathKeepsContext(t *testing.T) {
	in := `无法读取配置 /home/artex/config.json 中的密钥，请检查文件`
	got := sanitizeClientError(in)
	if !strings.Contains(got, "无法读取配置") || !strings.Contains(got, "请检查文件") {
		t.Errorf("path masking lost human context: %q", got)
	}
	if strings.Contains(got, "/home/artex/config.json") {
		t.Errorf("path not masked: %q", got)
	}
}
