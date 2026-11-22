package db

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func setMasterKey(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(masterKeyEnv)
	if err := os.Setenv(masterKeyEnv, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(masterKeyEnv, old)
		} else {
			_ = os.Unsetenv(masterKeyEnv)
		}
	})
}

// TestSecretNoMasterKeyIsPassthrough is THE backward-compatibility guarantee:
// an install that never sets ARTEX_MASTER_KEY behaves byte-for-byte as before.
func TestSecretNoMasterKeyIsPassthrough(t *testing.T) {
	setMasterKey(t, "")
	for _, in := range []string{"", "sk-ant-plaintext-key", "postgres://u:p@h/db"} {
		sealed, err := SealSecret(in)
		if err != nil {
			t.Fatalf("SealSecret(%q): %v", in, err)
		}
		if sealed != in {
			t.Errorf("plaintext mode changed value: in=%q out=%q", in, sealed)
		}
		opened, err := OpenSecret(in)
		if err != nil {
			t.Fatalf("OpenSecret(%q): %v", in, err)
		}
		if opened != in {
			t.Errorf("plaintext mode changed read: in=%q out=%q", in, opened)
		}
	}
}

// TestSecretRoundTripPassphrase covers the passphrase-derived key path.
func TestSecretRoundTripPassphrase(t *testing.T) {
	setMasterKey(t, "a-long-passphrase-not-a-base64-blob")
	const plain = "sk-ant-api03-supersecret-value"
	sealed, err := SealSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, secretPrefix) {
		t.Fatalf("ciphertext missing prefix: %q", sealed)
	}
	if strings.Contains(sealed, plain) {
		t.Fatalf("ciphertext leaked plaintext: %q", sealed)
	}
	opened, err := OpenSecret(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if opened != plain {
		t.Errorf("round trip mismatch: got %q want %q", opened, plain)
	}
}

// TestSecretRoundTripBase64Key covers the recommended 32-byte base64 key path
// and confirms the random nonce makes two encryptions of the same value differ.
func TestSecretRoundTripBase64Key(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	setMasterKey(t, base64.StdEncoding.EncodeToString(raw))
	const plain = "brave-secret-key-12345"
	a, err := SealSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two encryptions of same value are identical — nonce not random")
	}
	for _, sealed := range []string{a, b} {
		opened, err := OpenSecret(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if opened != plain {
			t.Errorf("round trip mismatch: got %q want %q", opened, plain)
		}
	}
}

// TestSecretLegacyPlaintextReads: a ciphertext-prefix-less value is plaintext,
// which is what makes upgrading an existing DB seamless.
func TestSecretLegacyPlaintextReads(t *testing.T) {
	setMasterKey(t, "some-key")
	const legacy = "sk-old-plaintext-from-before-upgrade"
	opened, err := OpenSecret(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if opened != legacy {
		t.Errorf("legacy plaintext altered: got %q want %q", opened, legacy)
	}
}

// TestSecretWrongOrMissingKeyFailsLoudly ensures a changed/unset master key
// never silently yields garbage that would be sent to a provider.
func TestSecretWrongOrMissingKeyFailsLoudly(t *testing.T) {
	setMasterKey(t, "key-A")
	sealed, err := SealSecret("top-secret")
	if err != nil {
		t.Fatal(err)
	}

	// Missing key → specific error.
	setMasterKey(t, "")
	if _, err := OpenSecret(sealed); err == nil {
		t.Error("opening ciphertext with no master key should fail")
	}
	// Wrong key → decrypt error.
	setMasterKey(t, "key-B-completely-different")
	if _, err := OpenSecret(sealed); err == nil {
		t.Error("opening ciphertext with wrong master key should fail")
	}
	// Corrupt payload → format error, no panic.
	setMasterKey(t, "key-A")
	if _, err := OpenSecret(secretPrefix + "!!!not-base64!!!"); err == nil {
		t.Error("corrupt ciphertext should fail")
	}
}

func TestSecretEmptyValue(t *testing.T) {
	setMasterKey(t, "key")
	if got, err := SealSecret(""); err != nil || got != "" {
		t.Errorf("empty seal: got=%q err=%v", got, err)
	}
	if got, err := OpenSecret(""); err != nil || got != "" {
		t.Errorf("empty open: got=%q err=%v", got, err)
	}
}
