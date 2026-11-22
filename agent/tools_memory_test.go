package agent

import (
	"testing"
	"time"
)

func TestParseMemoryTime(t *testing.T) {
	// 空串 = 不设置。
	if v, err := parseMemoryTime(""); v != nil || err != nil {
		t.Errorf("空串应返回 nil,nil，得 (%v,%v)", v, err)
	}
	if v, err := parseMemoryTime("   "); v != nil || err != nil {
		t.Errorf("空白串应返回 nil,nil，得 (%v,%v)", v, err)
	}
	// RFC3339。
	v, err := parseMemoryTime("2026-12-01T08:00:00Z")
	if err != nil || v == nil {
		t.Fatalf("RFC3339 应解析成功，得 (%v,%v)", v, err)
	}
	if v.UTC().Format(time.RFC3339) != "2026-12-01T08:00:00Z" {
		t.Errorf("解析值不符：%s", v.Format(time.RFC3339))
	}
	// 2006-01-02。
	v, err = parseMemoryTime("2026-12-01")
	if err != nil || v == nil {
		t.Fatalf("2006-01-02 应解析成功，得 (%v,%v)", v, err)
	}
	// 非法。
	if _, err := parseMemoryTime("not-a-date"); err == nil {
		t.Error("非法格式应报错")
	}
}
