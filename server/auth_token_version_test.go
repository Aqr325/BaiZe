package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// fakeAtomicSettings is an in-memory atomicSettingsWriter for version tests.
type fakeAtomicSettings struct {
	mu     sync.Mutex
	values map[string]string
	fail   bool
}

func newFakeAtomicSettings() *fakeAtomicSettings {
	return &fakeAtomicSettings{values: map[string]string{}}
}

func (f *fakeAtomicSettings) SetSettingsAtomic(_ context.Context, values map[string]string) error {
	if f.fail {
		return errors.New("injected failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range values {
		f.values[k] = v
	}
	return nil
}

func testJWTKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func TestSignVerifyJWTTokenVersion(t *testing.T) {
	key := testJWTKey()
	v1, err := signJWT(key, "1")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(v1, key, "1") {
		t.Fatal("token with tv=1 must verify against version 1")
	}
	if verifyJWT(v1, key, "2") {
		t.Fatal("token with tv=1 must NOT verify against version 2")
	}
	// Default (variadic omitted) is version 1.
	if !verifyJWT(v1, key) {
		t.Fatal("default verify must accept a version-1 token")
	}
	// Tokens issued before the mechanism shipped have no "tv" claim; treat as 1.
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "白泽",
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(legacy, key, "1") {
		t.Fatal("legacy token without tv must be treated as version 1")
	}
	if verifyJWT(legacy, key, "2") {
		t.Fatal("legacy token must be rejected once version is bumped")
	}
}

func TestVerifyJWTRejectsUnexpectedSigningMethod(t *testing.T) {
	key := testJWTKey()
	// HS512 is still an HMAC, but WithValidMethods restricts to HS256.
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"tv": "1"}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(tok, key, "1") {
		t.Fatal("HS512 token must be rejected (only HS256 is allowed)")
	}
}

func TestCommitPasswordChangeRevokesOldToken(t *testing.T) {
	key := testJWTKey()
	s := &Server{jwtKey: key, authTokenVer: defaultAuthTokenVersion}
	oldToken, err := signJWT(key, s.currentAuthTokenVersion())
	if err != nil {
		t.Fatal(err)
	}

	store := newFakeAtomicSettings()
	if _, err := s.commitPasswordChange(context.Background(), store, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if got := s.currentAuthTokenVersion(); got != "2" {
		t.Fatalf("version=%q, want 2", got)
	}
	if store.values[authPassKey] != "new-hash" || store.values[authTokenVersionKey] != "2" {
		t.Fatalf("atomic write missing values: %#v", store.values)
	}

	if verifyJWT(oldToken, key, s.currentAuthTokenVersion()) {
		t.Fatal("old token must be rejected after password change bumps the version")
	}
	newToken, err := signJWT(key, s.currentAuthTokenVersion())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(newToken, key, s.currentAuthTokenVersion()) {
		t.Fatal("new token issued at the bumped version must verify")
	}
}

func TestCommitPasswordChangeFailsClosed(t *testing.T) {
	key := testJWTKey()
	s := &Server{jwtKey: key, authTokenVer: "5"}
	store := newFakeAtomicSettings()
	store.fail = true
	if _, err := s.commitPasswordChange(context.Background(), store, "new-hash"); err == nil {
		t.Fatal("expected injected failure")
	}
	if got := s.currentAuthTokenVersion(); got != "5" {
		t.Fatalf("failed commit must not change cached version, got %q", got)
	}
}

func TestNextAuthTokenVersion(t *testing.T) {
	for in, want := range map[string]string{
		"": "2", "1": "2", "9": "10", "not-a-number": "2",
	} {
		if got := nextAuthTokenVersion(in); got != want {
			t.Errorf("nextAuthTokenVersion(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestExtractTokenQueryOnlyOnSSERoutes(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/api/logs/stream", true},
		{"/api/update/stream", true},
		{"/api/exploration/activity/stream", true},
		{"/api/side-questions/123/events", true},
		{"/api/tasks", false},
		{"/api/settings", false},
		{"/api/auth/login", false},
		{"/api/side-questions/123/cancel", false},
	} {
		r := httptest.NewRequest("GET", tc.path+"?token=abc123", nil)
		if got := extractToken(r); (got == "abc123") != tc.want {
			t.Errorf("path=%s token=%q want query honoured=%v", tc.path, got, tc.want)
		}
	}
	// Authorization header always wins.
	r := httptest.NewRequest("GET", "/api/tasks?token=query", nil)
	r.Header.Set("Authorization", "Bearer header")
	if got := extractToken(r); got != "header" {
		t.Errorf("bearer header must win, got %q", got)
	}
}
