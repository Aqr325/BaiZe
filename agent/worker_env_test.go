package agent

import (
	"os/exec"
	"testing"
)

func hasEnvEntry(env []string, key string) bool {
	for _, e := range env {
		if len(e) > len(key) && e[:len(key)] == key && e[len(key)] == '=' {
			return true
		}
	}
	return false
}

func envContains(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func TestProxyEnvAlwaysBlanksSecrets(t *testing.T) {
	secretKeys := []string{
		"ARTEX_PG_DSN", "ARTEX_MASTER_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
	}
	for _, tc := range []struct {
		name, proxy, ca string
	}{
		{"no-proxy", "", ""},
		{"proxy-only", "http://127.0.0.1:8787", ""},
		{"proxy-and-ca", "http://127.0.0.1:8787", "/tmp/ca.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := proxyEnv(tc.proxy, tc.ca)
			if len(env) == 0 {
				t.Fatal("proxyEnv returned empty — withEnv would inherit raw secrets")
			}
			for _, k := range secretKeys {
				found := false
				for _, e := range env {
					if e == k+"=" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("secret %s not blanked in %s", k, tc.name)
				}
			}
		})
	}
}

func TestProxyEnvKeepsEgressAndCA(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:8787", "/tmp/ca.pem")
	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:8787", "ALL_PROXY=http://127.0.0.1:8787",
		"NODE_USE_ENV_PROXY=1", "SSL_CERT_FILE=/tmp/ca.pem", "NODE_EXTRA_CA_CERTS=/tmp/ca.pem",
	} {
		if !envContains(env, want) {
			t.Errorf("missing egress/CA entry %q", want)
		}
	}
	// no proxy → no egress entries, but secrets still masked
	bare := proxyEnv("", "")
	if hasEnvEntry(bare, "HTTP_PROXY") {
		t.Error("no-proxy path unexpectedly set HTTP_PROXY")
	}
}

// TestExecDedupLastWins verifies the SDK's documented assumption: appending
// "KEY=" after an inherited value blanks it in the child environment. This is
// the mechanism sensitiveEnvMask relies on; pin it so a Go/platform change that
// breaks dedup is caught instead of silently leaking secrets.
func TestExecDedupLastWins(t *testing.T) {
	cmd := exec.Command("sh", "-c", "printf '%s' \"$ARTEX_PG_DSN\"")
	cmd.Env = append([]string{"ARTEX_PG_DSN=secret-value"}, sensitiveEnvMask()...)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("shell unavailable on this host: %v", err)
	}
	if string(out) != "" {
		t.Fatalf("secret leaked through env dedup: got %q", out)
	}
}
