package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	os.Unsetenv("ASPM_HTTP_ADDR")
	os.Unsetenv("ASPM_DATABASE_DSN")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q, want %q", cfg.HTTP.Addr, ":8080")
	}
	if cfg.HTTP.ReadTimeoutSec != 30 {
		t.Errorf("HTTP.ReadTimeoutSec = %d, want 30", cfg.HTTP.ReadTimeoutSec)
	}
	if cfg.Database.MaxConns != 10 {
		t.Errorf("Database.MaxConns = %d, want 10", cfg.Database.MaxConns)
	}
	if !cfg.Database.AutoMigrate {
		t.Error("Database.AutoMigrate should be true")
	}
	if cfg.Scanners.WorkDir != "/tmp/aspm-work" {
		t.Errorf("Scanners.WorkDir = %q, want %q", cfg.Scanners.WorkDir, "/tmp/aspm-work")
	}
	if len(cfg.QualityGate.FailOn) == 0 {
		t.Error("QualityGate.FailOn should have default rules")
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	t.Setenv("ASPM_HTTP_ADDR", ":9090")
	t.Setenv("ASPM_DATABASE_DSN", "postgres://localhost/test")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.HTTP.Addr != ":9090" {
		t.Errorf("HTTP.Addr = %q, want %q", cfg.HTTP.Addr, ":9090")
	}
}
