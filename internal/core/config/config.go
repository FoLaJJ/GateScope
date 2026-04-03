package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"   mapstructure:"server"`
	Database DatabaseConfig `yaml:"database" mapstructure:"database"`
	Scanner  ScannerConfig  `yaml:"scanner"  mapstructure:"scanner"`
	Auth     AuthConfig     `yaml:"auth"     mapstructure:"auth"`
	Alert    AlertConfig    `yaml:"alert"    mapstructure:"alert"`
	GeoIP    GeoIPConfig    `yaml:"geoip"    mapstructure:"geoip"`
	Intel    IntelConfig    `yaml:"intel"    mapstructure:"intel"`
	Log      LogConfig      `yaml:"log"      mapstructure:"log"`
}

type ServerConfig struct {
	Host string `yaml:"host" mapstructure:"host"`
	Port int    `yaml:"port" mapstructure:"port"`
}

type DatabaseConfig struct {
	Driver      string        `yaml:"driver"       mapstructure:"driver"`
	DSN         string        `yaml:"dsn"          mapstructure:"dsn"`
	MaxOpenConn int           `yaml:"max_open_conn" mapstructure:"max_open_conn"`
	MaxIdleConn int           `yaml:"max_idle_conn" mapstructure:"max_idle_conn"`
	MaxLifetime time.Duration `yaml:"max_lifetime" mapstructure:"max_lifetime"`
}

type ScannerConfig struct {
	DefaultPorts []int         `yaml:"default_ports" mapstructure:"default_ports"`
	Timeout      time.Duration `yaml:"timeout"       mapstructure:"timeout"`
	Concurrency  int           `yaml:"concurrency"   mapstructure:"concurrency"`
	RateLimit    int           `yaml:"rate_limit"    mapstructure:"rate_limit"`
	L1ScanMode   string        `yaml:"l1_scan_mode"  mapstructure:"l1_scan_mode"`
	EnableMDNS   bool          `yaml:"enable_mdns"   mapstructure:"enable_mdns"`
	MDNSTimeout  time.Duration `yaml:"mdns_timeout"  mapstructure:"mdns_timeout"`
}

type AuthConfig struct {
	JWTSecret string        `yaml:"jwt_secret" mapstructure:"jwt_secret"`
	Username  string        `yaml:"username"   mapstructure:"username"`
	Password  string        `yaml:"password"   mapstructure:"password"`
	TokenTTL  time.Duration `yaml:"token_ttl"  mapstructure:"token_ttl"`
}

type AlertConfig struct {
	WebhookURL     string        `yaml:"webhook_url"     mapstructure:"webhook_url"`
	WebhookTimeout time.Duration `yaml:"webhook_timeout" mapstructure:"webhook_timeout"`
	Enabled        bool          `yaml:"enabled"         mapstructure:"enabled"`
}

type GeoIPConfig struct {
	DatabasePath string `yaml:"database_path" mapstructure:"database_path"`
	LicenseKey   string `yaml:"license_key"   mapstructure:"license_key"`
}

type IntelConfig struct {
	FOFA FOFAConfig `yaml:"fofa" mapstructure:"fofa"`
}

type FOFAConfig struct {
	Email  string `yaml:"email"   mapstructure:"email"`
	APIKey string `yaml:"api_key" mapstructure:"api_key"`
}

type LogConfig struct {
	Level  string `yaml:"level"  mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
	File   string `yaml:"file"   mapstructure:"file"`
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)

	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "_data/agentscan.db")
	v.SetDefault("database.max_open_conn", 25)
	v.SetDefault("database.max_idle_conn", 5)
	v.SetDefault("database.max_lifetime", "5m")

	v.SetDefault("scanner.default_ports", []int{18789, 18792, 3000, 8080, 8888})
	v.SetDefault("scanner.timeout", "3s")
	v.SetDefault("scanner.concurrency", 100)
	v.SetDefault("scanner.rate_limit", 10000)
	v.SetDefault("scanner.l1_scan_mode", "connect")
	v.SetDefault("scanner.enable_mdns", true)
	v.SetDefault("scanner.mdns_timeout", "5s")

	v.SetDefault("auth.jwt_secret", "agentscan-dev-secret-change-me")
	v.SetDefault("auth.username", "admin")
	v.SetDefault("auth.password", "agentscan")
	v.SetDefault("auth.token_ttl", "24h")

	v.SetDefault("alert.webhook_timeout", "10s")
	v.SetDefault("alert.enabled", false)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "console")
}

// Load reads configuration from the given file path, environment variables,
// and defaults (in that priority order). Pass "" to skip file loading.
func Load(configPath string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetEnvPrefix("AGENTSCAN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("./_data")
		v.AddConfigPath("/etc/agentscan")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && configPath != "" {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1-65535, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" && cfg.Database.Driver != "postgres" {
		return fmt.Errorf("database.driver must be 'sqlite' or 'postgres', got %q", cfg.Database.Driver)
	}
	if cfg.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if cfg.Auth.JWTSecret == "" {
		return fmt.Errorf("auth.jwt_secret is required")
	}
	if cfg.Auth.JWTSecret == "agentscan-dev-secret-change-me" && cfg.Database.Driver == "postgres" {
		return fmt.Errorf("auth.jwt_secret must be changed from default in production (postgres mode)")
	}
	if cfg.Scanner.Concurrency < 1 {
		return fmt.Errorf("scanner.concurrency must be >= 1")
	}
	if cfg.Scanner.L1ScanMode != "" && cfg.Scanner.L1ScanMode != "connect" && cfg.Scanner.L1ScanMode != "syn" {
		return fmt.Errorf("scanner.l1_scan_mode must be 'connect' or 'syn', got %q", cfg.Scanner.L1ScanMode)
	}
	if cfg.Scanner.Timeout <= 0 {
		return fmt.Errorf("scanner.timeout must be > 0")
	}
	return nil
}

// Default returns a Config with all defaults applied (no file, no env).
// Useful for tests and backward compatibility.
func Default() *Config {
	cfg, _ := Load("")
	return cfg
}
