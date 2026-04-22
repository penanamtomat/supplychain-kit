// Package config wires Viper-backed configuration loaded from defaults,
// configs/aspm.yaml, and ASPM_-prefixed environment variables (in that order).
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config is the root configuration struct.
type Config struct {
	HTTP        HTTPConfig        `mapstructure:"http"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Redis       RedisConfig       `mapstructure:"redis"`
	Scanners    ScannersConfig    `mapstructure:"scanners"`
	Remediation RemediationConfig `mapstructure:"remediation"`
	QualityGate QualityGateConfig `mapstructure:"quality_gate"`
}

type HTTPConfig struct {
	Addr           string `mapstructure:"addr"`
	ReadTimeoutSec int    `mapstructure:"read_timeout_sec"`
}

type DatabaseConfig struct {
	DSN         string `mapstructure:"dsn"`
	MaxConns    int    `mapstructure:"max_conns"`
	AutoMigrate bool   `mapstructure:"auto_migrate"`
}

type RedisConfig struct {
	URL string `mapstructure:"url"`
}

type ScannersConfig struct {
	WorkDir          string `mapstructure:"work_dir"`
	MaxParallelSyft  int    `mapstructure:"max_parallel_syft"`
	MaxParallelGrype int    `mapstructure:"max_parallel_grype"`
	MaxParallelSAST  int    `mapstructure:"max_parallel_sast"`
	GrypeDBMaxAgeHrs int    `mapstructure:"grype_db_max_age_hrs"`
}

type RemediationConfig struct {
	BaseURL     string `mapstructure:"base_url"`
	LLMProvider string `mapstructure:"llm_provider"`
	GitHubToken string `mapstructure:"github_token"`
}

type QualityGateConfig struct {
	FailOn []GateRule `mapstructure:"fail_on"`
	WarnOn []GateRule `mapstructure:"warn_on"`
}

type GateRule struct {
	Severity  string `mapstructure:"severity"`
	Reachable *bool  `mapstructure:"reachable"`
	MaxCount  int    `mapstructure:"max_count"`
}

// Load reads configuration from disk and the environment.
// path is optional; pass "" to use the default search locations.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	v.SetDefault("http.addr", ":8080")
	v.SetDefault("http.read_timeout_sec", 30)
	v.SetDefault("database.max_conns", 10)
	v.SetDefault("database.auto_migrate", true)
	v.SetDefault("scanners.work_dir", "/tmp/aspm-work")
	v.SetDefault("scanners.max_parallel_syft", 4)
	v.SetDefault("scanners.max_parallel_grype", 4)
	v.SetDefault("scanners.max_parallel_sast", 2)
	v.SetDefault("scanners.grype_db_max_age_hrs", 24)
	v.SetDefault("remediation.base_url", "http://localhost:9090")
	v.SetDefault("remediation.llm_provider", "anthropic")

	// Default quality gate: fail on any Critical, warn on any High.
	// These are overridden by quality_gate entries in the config file.
	v.SetDefault("quality_gate.fail_on", []map[string]interface{}{
		{"severity": "critical"},
	})
	v.SetDefault("quality_gate.warn_on", []map[string]interface{}{
		{"severity": "high"},
	})

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("aspm")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/aspm")
	}

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is fine; everything has a default or env override.
		var nf viper.ConfigFileNotFoundError
		if !errors.As(err, &nf) {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	v.SetEnvPrefix("ASPM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}
