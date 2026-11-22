package enrich

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

// TestHTTPProbeNoPanic ensures the httpx-based probe (doHTTP) and the record
// helpers tolerate a nil AssetStore (no DB in unit tests) instead of panicking.
// The old self-rolled probe's User-Agent regression test was removed because
// doHTTP now delegates UA/fingerprinting to httpx (projectdiscovery/useragent),
// no longer using httpidentity.
func TestHTTPProbeNoPanic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>baize</title></head><body>ok</body></html>"))
	}))
	defer server.Close()

	e := &Engine{as: nil}
	// httpx runs against the local server; OnResult → recordHTTP must guard nil as.
	e.doHTTP(1, server.URL)
	// direct helper with nil store must not panic either.
	e.recordHTTP(runner.Result{URL: server.URL})
	if e.as != nil {
		t.Fatal("expected nil AssetStore in test engine")
	}
}
