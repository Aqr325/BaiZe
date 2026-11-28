// Command skillprovenance regenerates the skill provenance manifest.
//
// ⑤ marketplace 溯源 hash 校验：为 skills/ 下每个 skill 重算内容 tree-hash
// 并写 <skillDir>/provenance.json，同时补来源元数据（origin/license）。
//
// 用法：
//
//	go run ./cmd/skillprovenance -dir skills         # 重钉所有 skill 的 tree-hash
//	go run ./cmd/skillprovenance -dir skills -verify # 只校验不改清单（退出码 2=有漂移）
//
// 清单由服务器加载时校验：内容漂移/篡改 → 隔离 + 落审计；正常内容变更后
// 需重跑本命令重新钉版（这是防投毒的有意摩擦：任何内容变化都要显式重钉）。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/baize/server"
)

// origins records each skill's verified source. Only assert what is verifiable:
// the two large third-party libraries and the five first-party suite skills.
// cyber-monster is the only gitignored skill (fetched as a tarball per .gitignore),
// so its provenance tree_hash is its sole integrity control — pin it deliberately.
var origins = map[string][2]string{
	"agentic-detections":      {"https://github.com/ThreatDefence/agentic-attack-detections", "MIT"},
	"anthropic-cybersecurity": {"https://github.com/mukul975/Anthropic-Cybersecurity-Skills", ""},
	"cyber-monster":           {"https://github.com/W4L33Dx/Cyber-Monster", ""},
	"api-recon":               {"local:self-made", ""},
	"evidence-chain":          {"local:self-made", ""},
	"pentest-assistant":       {"local:self-made", ""},
	"playwright-cli":          {"local:self-made", ""},
	"red-team-ops":            {"https://github.com/JoasASantos/Awesome-Red-Team-Operations", ""},
	"scopesentry":             {"local:self-made", ""},
	"src-vuln-scanner":        {"local:self-made", ""},
}

func main() {
	dir := flag.String("dir", "skills", "skill directory to scan (default skills)")
	verify := flag.Bool("verify", false, "verify every skill against the manifest instead of re-pinning")
	flag.Parse()

	abs, _ := filepath.Abs(*dir)

	if *verify {
		// verify mode: report provenance status per skill (does not write).
		entries, err := os.ReadDir(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skillprovenance: %v\n", err)
			os.Exit(1)
		}
		bad := 0
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			name := e.Name()
			pc := server.CheckSkillProvenance(*dir, name)
			fmt.Printf("%-28s %s\n", name, pc.Status)
			if pc.Status != "ok" {
				fmt.Printf("  %-26s %s\n", "", pc.Detail)
				bad++
			}
		}
		fmt.Printf("skillprovenance: %d skill(s) not provably pinned in %s\n", bad, abs)
		if bad > 0 {
			os.Exit(2)
		}
		return
	}

	originFn := func(name string) (string, string) {
		if o, ok := origins[name]; ok {
			return o[0], o[1]
		}
		return "", ""
	}
	count, err := server.RegenerateSkillProvenance(*dir, originFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skillprovenance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("skillprovenance: re-pinned %d skills -> %s\n", count, filepath.Join(abs, "provenance.json"))
}
