package db

// Field-level encryption for secrets stored in PostgreSQL (LLM api keys,
// web-search provider keys). Design goals, in priority order:
//
//  1. ZERO behavior change when no master key is configured. Every deployment
//     that upgrades without ARTEX_MASTER_KEY keeps reading/writing plaintext
//     exactly as before — no data becomes unreadable, no migration required.
//  2. When ARTEX_MASTER_KEY IS set, new writes are AES-256-GCM encrypted with a
//     random nonce; reads transparently decrypt. Existing plaintext rows keep
//     working and are opportunistically upgraded the next time they are saved.
//  3. Ciphertext is self-describing (enc:v1: prefix), so a key change or an
//     unset key produces a loud, specific error rather than silent garbage.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// masterKeyEnv is the only configuration surface. Set it to either a
	// base64-encoded 32-byte key (recommended: `openssl rand -base64 32`) or any
	// passphrase (SHA-256-derived). Empty = encryption disabled.
	masterKeyEnv = "ARTEX_MASTER_KEY"

	secretPrefix = "enc:v1:"
)

var errNoMasterKey = errors.New("值已加密，但环境变量 " + masterKeyEnv + " 未设置或为空，无法解密")

// masterKey resolves the encryption key on each call. Reading the environment
// is cheap and keeps configuration dynamic (and tests simple); these helpers are
// only invoked on config load/save, never on a hot path.
func masterKey() []byte {
	v := strings.TrimSpace(os.Getenv(masterKeyEnv))
	if v == "" {
		return nil // encryption disabled
	}
	// Preferred: base64 of exactly 32 bytes.
	if raw, err := base64.StdEncoding.DecodeString(v); err == nil && len(raw) == 32 {
		return raw
	}
	// Fallback: derive 32 bytes from a passphrase.
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}

// SealSecret encrypts a secret for storage. With no master key configured it
// returns the input unchanged (plaintext compatibility mode). Empty values are
// always returned as-is so NULLIF(...) semantics in callers still hold.
func SealSecret(plain string) (string, error) {
	if plain == "" {
		return plain, nil
	}
	key := masterKey()
	if key == nil {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// gcm.Seal appends ciphertext to nonce, so the payload is nonce||ciphertext.
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenSecret decrypts a stored secret. Plaintext values (no enc:v1: prefix) are
// returned unchanged, which is what makes upgrades backward-compatible. A
// ciphertext with a missing or changed master key yields a descriptive error.
func OpenSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil // legacy plaintext
	}
	key := masterKey()
	if key == nil {
		return "", errNoMasterKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("加密值格式损坏: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("加密值长度不足，数据可能被截断")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("解密失败（"+masterKeyEnv+" 可能已变更）: %w", err)
	}
	return string(plain), nil
}
