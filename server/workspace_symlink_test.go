package server

import (
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceSymlinkEscapeBlocked(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("TOP-SECRET-DO-NOT-LEAK"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "escape.txt")
	if err := os.Symlink(secretPath, link); err != nil {
		t.Skipf("creating symlinks requires privileges on this platform: %v", err)
	}

	s := &Server{m: &Manager{dir: base}}

	// Read must not follow a symlink that leaves the workspace.
	w := httptest.NewRecorder()
	s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path=escape.txt", nil))
	if w.Code != 404 {
		t.Fatalf("wsRead status=%d body=%s; symlink escape must be rejected", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "TOP-SECRET") {
		t.Fatalf("wsRead leaked the out-of-workspace file: %s", w.Body.String())
	}

	// Download must be confined too.
	w = httptest.NewRecorder()
	s.wsDownload(w, httptest.NewRequest("GET", "/api/workspace/download?path=escape.txt", nil))
	if w.Code != 404 || strings.Contains(w.Body.String(), "TOP-SECRET") {
		t.Fatalf("wsDownload status=%d body=%s", w.Code, w.Body.String())
	}

	// Write through the symlink must fail and leave the outside file untouched.
	w = httptest.NewRecorder()
	body := strings.NewReader(`{"path":"escape.txt","content":"OVERWRITTEN"}`)
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", body))
	if w.Code == 200 {
		t.Fatalf("wsWrite succeeded through an escaping symlink: %s", w.Body.String())
	}
	data, err := os.ReadFile(secretPath)
	if err != nil || string(data) != "TOP-SECRET-DO-NOT-LEAK" {
		t.Fatalf("outside file was modified: %q, err=%v", data, err)
	}
}

func TestWorkspaceRootRelRejectsOutsidePaths(t *testing.T) {
	base := t.TempDir()
	s := &Server{m: &Manager{dir: base}}
	if _, err := s.wsRootRel(filepath.Join(base, "..", "outside", "secret.txt")); err == nil {
		t.Fatal("wsRootRel must reject a path that resolves outside the workspace")
	}
	rel, err := s.wsRootRel(filepath.Join(base, "a", "b.txt"))
	if err != nil || rel != path.Join("a", "b.txt") {
		t.Fatalf("wsRootRel inside path = %q, %v", rel, err)
	}
}

func TestWorkspaceNormalRoundTripStillWorks(t *testing.T) {
	base := t.TempDir()
	s := &Server{m: &Manager{dir: base}}

	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write",
		strings.NewReader(`{"path":"sub/hello.txt","content":"hello"}`)))
	if w.Code != 200 {
		t.Fatalf("write status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path=sub/hello.txt", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("read status=%d body=%s", w.Code, w.Body.String())
	}
}
