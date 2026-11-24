package server

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTestSkill creates a temp skill dir with a couple of files.
func writeTestSkill(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSkillTreeHashDeterministic(t *testing.T) {
	root := t.TempDir()
	writeTestSkill(t, root, "demo", map[string]string{
		"SKILL.md":         "name: demo\n",
		"scripts/a.py":     "print('a')\n",
		"scripts/sub/b.py": "print('b')\n",
	})
	h1, err := SkillTreeHash(root, "demo")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// re-read must be identical
	h2, err := SkillTreeHash(root, "demo")
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected sha256 hex (64), got %d", len(h1))
	}
}

func TestSkillTreeHashChangesOnContent(t *testing.T) {
	root := t.TempDir()
	writeTestSkill(t, root, "demo", map[string]string{
		"SKILL.md": "name: demo\n",
	})
	before, _ := SkillTreeHash(root, "demo")
	// append a file -> hash changes
	writeTestSkill(t, root, "demo", map[string]string{"extra.txt": "x"})
	after, _ := SkillTreeHash(root, "demo")
	if before == after {
		t.Fatal("hash should change when a file is added")
	}
	// modify content -> hash changes
	writeTestSkill(t, root, "demo", map[string]string{"extra.txt": "y"})
	after2, _ := SkillTreeHash(root, "demo")
	if after == after2 {
		t.Fatal("hash should change when a file's content changes")
	}
}

func TestCheckSkillProvenance(t *testing.T) {
	root := t.TempDir()
	writeTestSkill(t, root, "demo", map[string]string{"SKILL.md": "name: demo\n"})

	// no manifest -> missing (fail-open)
	pc := CheckSkillProvenance(root, "demo")
	if pc.Status != provMissing {
		t.Fatalf("expected missing, got %s", pc.Status)
	}

	// record -> ok
	if err := RecordSkillProvenance(root, "demo", "https://example.com/demo", "MIT"); err != nil {
		t.Fatalf("record: %v", err)
	}
	pc = CheckSkillProvenance(root, "demo")
	if pc.Status != provOK {
		t.Fatalf("expected ok, got %s (%s)", pc.Status, pc.Detail)
	}
	// manifest should have recorded origin
	man, _ := loadSkillProvenance(root)
	if man["demo"].Origin != "https://example.com/demo" || man["demo"].License != "MIT" {
		t.Fatalf("origin/license not recorded: %+v", man["demo"])
	}

	// tamper -> mismatch (isolate)
	writeTestSkill(t, root, "demo", map[string]string{"SKILL.md": "name: demo\n# tampered\n"})
	pc = CheckSkillProvenance(root, "demo")
	if pc.Status != provMismatch {
		t.Fatalf("expected mismatch after tamper, got %s", pc.Status)
	}
}

func TestRecordSkillProvenancePreservesMeta(t *testing.T) {
	root := t.TempDir()
	writeTestSkill(t, root, "demo", map[string]string{"SKILL.md": "name: demo\n"})
	_ = RecordSkillProvenance(root, "demo", "https://example.com/demo", "MIT")
	// re-record with empty meta keeps origin/license, updates hash
	_ = RecordSkillProvenance(root, "demo", "", "")
	man, _ := loadSkillProvenance(root)
	if man["demo"].Origin != "https://example.com/demo" || man["demo"].License != "MIT" {
		t.Fatalf("meta not preserved: %+v", man["demo"])
	}
}

func TestRegenerateSkillProvenance(t *testing.T) {
	root := t.TempDir()
	writeTestSkill(t, root, "a", map[string]string{"SKILL.md": "name: a\n"})
	writeTestSkill(t, root, "b", map[string]string{"SKILL.md": "name: b\n"})
	// skip dot-dirs
	writeTestSkill(t, root, ".hidden", map[string]string{"SKILL.md": "name: hidden\n"})

	count, err := RegenerateSkillProvenance(root, nil)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 skills pinned (dot-dir skipped), got %d", count)
	}
	if pc := CheckSkillProvenance(root, "a"); pc.Status != provOK {
		t.Fatalf("a should be ok, got %s", pc.Status)
	}
	if pc := CheckSkillProvenance(root, "b"); pc.Status != provOK {
		t.Fatalf("b should be ok, got %s", pc.Status)
	}
	// originFn supplies metadata
	count2, _ := RegenerateSkillProvenance(root, func(name string) (string, string) {
		return "https://example.com/" + name, "Apache-2.0"
	})
	if count2 != 2 {
		t.Fatalf("expected 2 on regen, got %d", count2)
	}
	man, _ := loadSkillProvenance(root)
	if man["a"].Origin != "https://example.com/a" {
		t.Fatalf("originFn not applied: %+v", man["a"])
	}
}
