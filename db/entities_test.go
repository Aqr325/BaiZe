package db

import "testing"

// 实体提取是纯规则、无 DB、无 LLM——可以完全离线单测。
// 覆盖：IP / 域名 / 路径 / 文件 / 端口 / CVE / 版本，去重，纯 IP 不当域名，
// 版本号不误吞 IP 段。

func TestExtractEntitiesIPs(t *testing.T) {
	hits := extractEntities("目标 10.10.5.3:8080，管理网段 192.168.1.0/24")
	var ipCount int
	for _, h := range hits {
		if h.Kind == EntityKindIP {
			ipCount++
		}
	}
	if ipCount != 2 {
		t.Errorf("应提取 2 个 IP，得 %d（hits=%v）", ipCount, hits)
	}
}

func TestExtractEntitiesDomainPathFile(t *testing.T) {
	text := "app.example.com 的 /admin/login.php 可绕过，备份 /backup/old.zip 存在"
	hits := extractEntities(text)
	kinds := map[string]bool{}
	names := map[string]bool{}
	for _, h := range hits {
		kinds[h.Kind] = true
		names[h.Name] = true
	}
	if !names["app.example.com"] || kinds[EntityKindDomain] == false {
		t.Errorf("应提取域名 app.example.com，得 %v", hits)
	}
	if !names["/admin/login.php"] {
		t.Errorf("应提取路径 /admin/login.php，得 %v", hits)
	}
	if !names["/backup/old.zip"] {
		t.Errorf("应提取路径 /backup/old.zip，得 %v", hits)
	}
	if !kinds[EntityKindPath] {
		t.Errorf("应有 path 类，得 %v", hits)
	}
}

func TestExtractEntitiesPortCVEVersion(t *testing.T) {
	text := "CVE-2024-3094 影响 openssh 8.9p1，端口 :2222 暴露，版本 1.2.3 已确认"
	hits := extractEntities(text)
	names := map[string]bool{}
	kinds := map[string]bool{}
	for _, h := range hits {
		names[h.Name] = true
		kinds[h.Kind] = true
	}
	if !names["CVE-2024-3094"] || !kinds[EntityKindCVE] {
		t.Errorf("应提取 CVE，得 %v", hits)
	}
	if !names["2222"] || !kinds[EntityKindPort] {
		t.Errorf("应提取端口 2222，得 %v", hits)
	}
	if !kinds[EntityKindVersion] {
		t.Errorf("应有 version 类，得 %v", hits)
	}
}

func TestExtractEntitiesSkipsIPv4AsDomain(t *testing.T) {
	// 纯 IP 不应被当成域名，也不该被当成版本号。
	hits := extractEntities("服务器 10.1.2.3 的版本")
	for _, h := range hits {
		if h.Name == "10.1.2.3" && h.Kind == EntityKindDomain {
			t.Errorf("纯 IP 被误判为域名：%+v", h)
		}
		if h.Name == "10.1.2.3" && h.Kind == EntityKindVersion {
			t.Errorf("纯 IP 被误判为版本：%+v", h)
		}
	}
}

func TestExtractEntitiesDedupes(t *testing.T) {
	hits := extractEntities("域名 app.example.com 出现两次 app.example.com")
	var n int
	for _, h := range hits {
		if h.Name == "app.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("同实体应去重，得 %d 次", n)
	}
}

func TestExtractEntitiesEmpty(t *testing.T) {
	if hits := extractEntities(""); hits != nil {
		t.Errorf("空文本应无命中，得 %v", hits)
	}
	if hits := extractEntities("   "); hits != nil {
		t.Errorf("空白文本应无命中，得 %v", hits)
	}
}

func TestEntityVisibleWhere(t *testing.T) {
	// 空名 = 不过滤（返回 false）。
	if s, ok, n := entityVisibleWhere("", 1); ok || s != "" || n != 1 {
		t.Errorf("空实体应不过滤，得 (%q,%v,%d)", s, ok, n)
	}
	// 有名字 = 生成占位符且推进参数下标。
	s, ok, n := entityVisibleWhere("app.example.com", 3)
	if !ok {
		t.Fatal("非空实体应过滤")
	}
	if n != 4 {
		t.Errorf("参数下标应推进到 4，得 %d", n)
	}
	if s == "" {
		t.Error("应生成 SQL 片段")
	}
}

func TestToTextArray(t *testing.T) {
	if got := toTextArray([]string{"a", "b'}c"}); got != `{'a','b''}c'}` {
		t.Errorf("应转义单引号，得 %s", got)
	}
	if got := toTextArray(nil); got != "{}" {
		t.Errorf("空切片应得 {}，得 %s", got)
	}
}
