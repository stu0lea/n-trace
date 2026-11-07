package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateLegacyDataDir(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, "trace-audit-data")
	target := filepath.Join(base, "n-trace-data")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(legacy, "audit.db")
	if err := os.WriteFile(marker, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := migrateLegacyDataDir(target, legacy); got != target {
		t.Fatalf("got %q, want %q", got, target)
	}
	if _, err := os.Stat(filepath.Join(target, "audit.db")); err != nil {
		t.Fatalf("legacy data was not migrated: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy directory still exists")
	}
}

func TestMigrateLegacyDataDirKeepsExistingTarget(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, "trace-audit-data")
	target := filepath.Join(base, "n-trace-data")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := migrateLegacyDataDir(target, legacy); got != target {
		t.Fatalf("got %q, want %q", got, target)
	}
}
