package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsProbe(t *testing.T, requestOrigin, host string) (string, string) {
	t.Helper()
	r := httptest.NewRequest("OPTIONS", "http://"+host+"/api/settings", nil)
	if requestOrigin != "" {
		r.Header.Set("Origin", requestOrigin)
	}
	w := httptest.NewRecorder()
	cors(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("preflight must not reach the handler")
	})).ServeHTTP(w, r)
	return w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials")
}

func TestCORSNoWhitelistNeverSendsWildcardWithCredentials(t *testing.T) {
	oldVersion := BuildVersion
	BuildVersion = "1.2.3" // production build: no dev localhost reflection
	t.Cleanup(func() { BuildVersion = oldVersion })
	t.Setenv(corsAllowedOriginsEnv, "")

	origin, cred := corsProbe(t, "https://evil.test", "artex.internal:8787")
	if origin != "*" || cred != "" {
		t.Fatalf("wildcard origin=%q credentials=%q; want * without credentials", origin, cred)
	}

	// Localhost reflection is dev-only now.
	origin, cred = corsProbe(t, "http://127.0.0.1:3000", "127.0.0.1:8787")
	if origin != "*" || cred != "" {
		t.Fatalf("dev-only localhost reflection leaked into production: origin=%q credentials=%q", origin, cred)
	}
}

func TestCORSExplicitWhitelist(t *testing.T) {
	oldVersion := BuildVersion
	BuildVersion = "1.2.3"
	t.Cleanup(func() { BuildVersion = oldVersion })
	t.Setenv(corsAllowedOriginsEnv, "https://console.example.com, https://admin.example.com/path")

	for _, allowed := range []string{"https://console.example.com", "https://admin.example.com"} {
		origin, cred := corsProbe(t, allowed, "artex.internal:8787")
		if origin != allowed || cred != "true" {
			t.Fatalf("allowed origin=%q got origin=%q credentials=%q", allowed, origin, cred)
		}
	}
	origin, cred := corsProbe(t, "https://evil.test", "artex.internal:8787")
	if origin != "*" || cred != "" {
		t.Fatalf("unlisted origin got origin=%q credentials=%q", origin, cred)
	}
}

func TestCORSDevLocalhostReflection(t *testing.T) {
	oldVersion := BuildVersion
	BuildVersion = "dev"
	t.Cleanup(func() { BuildVersion = oldVersion })
	t.Setenv(corsAllowedOriginsEnv, "")

	origin, cred := corsProbe(t, "http://127.0.0.1:3000", "127.0.0.1:8787")
	if origin != "http://127.0.0.1:3000" || cred != "true" {
		t.Fatalf("dev localhost pairing origin=%q credentials=%q", origin, cred)
	}
}
