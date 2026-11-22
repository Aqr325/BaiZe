package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// uniqueName keeps these integration tests re-runnable against a dirty DB: a
// fixed profile name would collide with llm_profiles_name_key on a second run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// TestProfileAPIKeyEncryptedRoundTrip proves the full DB path: with a master
// key set, SaveProfile writes ciphertext (never plaintext) and ProfileByID
// returns the original key. This is the core P0-6 guarantee.
func TestProfileAPIKeyEncryptedRoundTrip(t *testing.T) {
	setMasterKey(t, "integration-master-key-32bytes!!")
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const plain = "sk-ant-api03-super-secret-value"
	id, err := d.SaveProfile(&LLMProfile{
		Name: uniqueName("t-secret-rt"), Format: "openai", Model: "m", APIKey: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })

	// Raw column must be ciphertext, not the plaintext key.
	var raw string
	if err := d.QueryRow(`SELECT api_key FROM llm_profiles WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, secretPrefix) {
		t.Fatalf("stored api_key is not encrypted: %q", raw)
	}
	if strings.Contains(raw, plain) {
		t.Fatalf("stored api_key leaked plaintext: %q", raw)
	}

	// Read path transparently decrypts.
	got, err := d.ProfileByID(id)
	if err != nil {
		t.Fatalf("ProfileByID: %v", err)
	}
	if got == nil {
		t.Fatal("ProfileByID returned nil")
	}
	if got.APIKey != plain {
		t.Errorf("decrypted key=%q want %q", got.APIKey, plain)
	}
	// Hint column still stores last-4 of plaintext (ListProfiles/UI needs it).
	// ProfileByID uses profileColsKey which omits the hint column, so read raw.
	var hint string
	if err := d.QueryRow(`SELECT api_key_hint FROM llm_profiles WHERE id=$1`, id).Scan(&hint); err != nil {
		t.Fatal(err)
	}
	if hint != "…"+plain[len(plain)-4:] {
		t.Errorf("hint=%q, want last-4 plaintext", hint)
	}
}

// TestProfileLegacyPlaintextStillReads: a row written before encryption was
// enabled (plaintext in DB) must still load when a master key is now set.
func TestProfileLegacyPlaintextStillReads(t *testing.T) {
	setMasterKey(t, "integration-master-key-32bytes!!")
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const plain = "sk-legacy-plaintext-key"
	id, err := d.SaveProfile(&LLMProfile{
		Name: uniqueName("t-secret-legacy"), Format: "openai", Model: "m", APIKey: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	// Simulate a pre-encryption row by writing plaintext directly.
	if _, err := d.Exec(`UPDATE llm_profiles SET api_key=$1 WHERE id=$2`, plain, id); err != nil {
		t.Fatal(err)
	}

	got, err := d.ProfileByID(id)
	if err != nil {
		t.Fatalf("ProfileByID on legacy row: %v", err)
	}
	if got == nil || got.APIKey != plain {
		t.Errorf("legacy key not read: got=%+v want %q", got, plain)
	}
}

// TestSettingsSecretRoundTrip covers the web-search key path (GetSecret/SetSecret).
func TestSettingsSecretRoundTrip(t *testing.T) {
	setMasterKey(t, "integration-master-key-32bytes!!")
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const key = "brave-search-secret-value"
	setting := uniqueName("t_secret_brave")
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, setting) })

	if err := d.SetSecret(setting, key); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := d.QueryRow(`SELECT value FROM settings WHERE key=$1`, setting).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(raw, secretPrefix) == false || strings.Contains(raw, key) {
		t.Fatalf("stored setting not encrypted: %q", raw)
	}
	got, ok, err := d.GetSecret(setting)
	if err != nil || !ok {
		t.Fatalf("GetSecret: ok=%v err=%v", ok, err)
	}
	if got != key {
		t.Errorf("GetSecret=%q want %q", got, key)
	}
}

// TestNoMasterKeyDBPathUnchanged: without a master key, a saved key is stored
// as plaintext and reads back identically — zero behavior change on upgrade.
func TestNoMasterKeyDBPathUnchanged(t *testing.T) {
	setMasterKey(t, "")
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	const plain = "sk-no-encryption-key"
	id, err := d.SaveProfile(&LLMProfile{
		Name: uniqueName("t-secret-plain"), Format: "openai", Model: "m", APIKey: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })

	var raw string
	if err := d.QueryRow(`SELECT api_key FROM llm_profiles WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != plain {
		t.Errorf("no-master-key stored=%q want plaintext %q", raw, plain)
	}
	got, err := d.ProfileByID(id)
	if err != nil || got == nil || got.APIKey != plain {
		t.Errorf("no-master-key read failed: got=%+v err=%v", got, err)
	}
}
