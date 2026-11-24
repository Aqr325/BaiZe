package agent

import (
	"strings"
	"testing"
)

func TestProxyEnvEmptyBlanksSecretsNoEgress(t *testing.T) {
	// Contract change (anti-honeypot hardening): no proxy no longer returns nil —
	// the secret mask must always be present, else withEnv inherits raw DSN/keys.
	env := proxyEnv("", "")
	if len(env) == 0 {
		t.Fatal("proxyEnv(\"\", \"\") returned empty — secrets would leak to Bash")
	}
	for _, e := range env {
		if strings.HasPrefix(e, "HTTP_PROXY=") || strings.HasPrefix(e, "SSL_CERT_FILE=") {
			t.Errorf("no-proxy path must not set egress/CA vars, got %q", e)
		}
	}
	for _, k := range []string{"ARTEX_PG_DSN", "ARTEX_MASTER_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		if !hasEnvEntry(env, k) {
			t.Errorf("no-proxy path missing secret mask for %s", k)
		}
	}
}

func TestProxyEnvSetsAllProxyForSocks5(t *testing.T) {
	// Capture-off egress path: a socks5 proxy, no MITM CA. ALL_PROXY must be set
	// (curl reads socks5 only from there), and no CA vars should appear.
	env := proxyEnv("socks5://10.0.0.1:1080", "")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "all_proxy="} {
		if !has(want) {
			t.Errorf("proxyEnv missing %s: %v", want, env)
		}
	}
	if has("SSL_CERT_FILE=") || has("CURL_CA_BUNDLE=") {
		t.Errorf("proxyEnv without CA must not inject CA vars: %v", env)
	}
}

func TestProxyEnvInjectsCAWhenRecording(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:8788", "/data/ca.pem")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "NODE_EXTRA_CA_CERTS="} {
		if !has(want) {
			t.Errorf("proxyEnv with CA missing %s: %v", want, env)
		}
	}
}
