package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeCapsOversizedBody(t *testing.T) {
	// Bodies beyond the cap must be rejected instead of fully buffered.
	body := strings.Repeat("A", maxDefaultRequestBodyBytes+1024)
	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(body))
	var out any
	if err := decode(req, &out); err == nil {
		t.Fatal("oversized body must fail to decode")
	}
	// Normal small payload still works.
	req2 := httptest.NewRequest("POST", "/api/x", strings.NewReader(`{"a":1}`))
	var out2 map[string]int
	if err := decode(req2, &out2); err != nil || out2["a"] != 1 {
		t.Fatalf("normal body failed: err=%v out=%v", err, out2)
	}
}
