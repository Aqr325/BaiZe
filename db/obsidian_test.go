package db

import (
	"context"
	"errors"
	"testing"
)

// SyncObsidian 空 vault 应在触碰 DB 前返回专用错误（纯逻辑，无需 PG）。
func TestSyncObsidianEmptyVault(t *testing.T) {
	s := &MemoryStore{} // db 为 nil
	_, err := s.SyncObsidian(context.Background(), ObsidianSyncOpts{})
	if !errors.Is(err, ErrObsidianVault) {
		t.Fatalf("空 vault 应返回 ErrObsidianVault，得 %v", err)
	}
}

// SyncObsidian 不存在的目录应返回错误（os 层，不碰 DB）。
func TestSyncObsidianMissingDir(t *testing.T) {
	s := &MemoryStore{}
	_, err := s.SyncObsidian(context.Background(), ObsidianSyncOpts{Vault: "/nonexistent/vault/path"})
	if err == nil {
		t.Fatalf("不存在的 vault 应返回错误")
	}
}

// ObsidianStatus 空 vault 返回未设置状态（不碰 DB）。
func TestObsidianStatusEmptyVault(t *testing.T) {
	s := &MemoryStore{}
	st, err := s.ObsidianStatus(context.Background(), "")
	if err != nil {
		t.Fatalf("空 vault 不应报错，得 %v", err)
	}
	if st.VaultSet {
		t.Errorf("空 vault 应 VaultSet=false")
	}
}
