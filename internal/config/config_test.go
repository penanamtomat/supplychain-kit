package config

import (
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Scanners.WorkDir != "/tmp/aspm-work" {
		t.Errorf("Scanners.WorkDir = %q, want %q", cfg.Scanners.WorkDir, "/tmp/aspm-work")
	}
	if cfg.Scanners.MaxParallelSyft != 4 {
		t.Errorf("Scanners.MaxParallelSyft = %d, want 4", cfg.Scanners.MaxParallelSyft)
	}
	if len(cfg.QualityGate.FailOn) == 0 {
		t.Error("QualityGate.FailOn should have default rules")
	}
	if len(cfg.QualityGate.WarnOn) == 0 {
		t.Error("QualityGate.WarnOn should have default rules")
	}
}

func TestLoad_QualityGateDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.QualityGate.FailOn[0].Severity != "critical" {
		t.Errorf("default fail_on severity = %q, want critical", cfg.QualityGate.FailOn[0].Severity)
	}
	if cfg.QualityGate.WarnOn[0].Severity != "high" {
		t.Errorf("default warn_on severity = %q, want high", cfg.QualityGate.WarnOn[0].Severity)
	}
}
