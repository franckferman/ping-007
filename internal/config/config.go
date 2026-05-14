package config

import (
	"fmt"
	"net"
	"os"

	"ping007/pkg/types"

	"github.com/spf13/viper"
)

type Config struct {
	Framework   FrameworkConfig            `mapstructure:"framework" yaml:"framework"`
	Network     NetworkConfig              `mapstructure:"network" yaml:"network"`
	Evasion     EvasionConfig              `mapstructure:"evasion" yaml:"evasion"`
	APTProfiles map[string]APTProfileConfig `mapstructure:"apt_profiles" yaml:"apt_profiles"`
	SIEM        SIEMConfig                 `mapstructure:"siem" yaml:"siem"`
	Security    SecurityConfig             `mapstructure:"security" yaml:"security"`
	Reporting   ReportingConfig            `mapstructure:"reporting" yaml:"reporting"`
}

type FrameworkConfig struct {
	Name        string `mapstructure:"name" yaml:"name"`
	Version     string `mapstructure:"version" yaml:"version"`
	Environment string `mapstructure:"environment" yaml:"environment"`
	DebugMode   bool   `mapstructure:"debug_mode" yaml:"debug_mode"`
	LogLevel    string `mapstructure:"log_level" yaml:"log_level"`
}

type NetworkConfig struct {
	AuthorizedTargets []string `mapstructure:"authorized_targets" yaml:"authorized_targets"`
	ForbiddenTargets  []string `mapstructure:"forbidden_targets" yaml:"forbidden_targets"`
	DefaultInterface  string   `mapstructure:"default_interface" yaml:"default_interface"`
	Timeout           int      `mapstructure:"timeout" yaml:"timeout"`
	MaxPacketSize     int      `mapstructure:"max_packet_size" yaml:"max_packet_size"`
}

// EvasionConfig contains evasion technique settings
type EvasionConfig struct {
	CryptoAgility               CryptoAgilityConfig `mapstructure:"crypto_agility" yaml:"crypto_agility"`
	AntiSandbox                 AntiSandboxConfig   `mapstructure:"anti_sandbox" yaml:"anti_sandbox"`
	TimingEvasion               TimingEvasionConfig `mapstructure:"timing_evasion" yaml:"timing_evasion"`
	TrafficAnalysisResistance   bool                `mapstructure:"traffic_analysis_resistance" yaml:"traffic_analysis_resistance"`
	PaddingSizes                []int               `mapstructure:"padding_sizes" yaml:"padding_sizes"`
	FakeDataInjectionRate       float64             `mapstructure:"fake_data_injection_rate" yaml:"fake_data_injection_rate"`
}

type CryptoAgilityConfig struct {
	Enabled          bool     `mapstructure:"enabled" yaml:"enabled"`
	Algorithms       []string `mapstructure:"algorithms" yaml:"algorithms"`
	RotationInterval int      `mapstructure:"rotation_interval" yaml:"rotation_interval"`
	DefaultAlgorithm string   `mapstructure:"default_algorithm" yaml:"default_algorithm"`
}

// AntiSandboxConfig contains anti-sandbox settings
type AntiSandboxConfig struct {
	Enabled       bool     `mapstructure:"enabled" yaml:"enabled"`
	StrictMode    bool     `mapstructure:"strict_mode" yaml:"strict_mode"`
	Checks        []string `mapstructure:"checks" yaml:"checks"`
	MinUptime     int      `mapstructure:"min_uptime" yaml:"min_uptime"`
	MinProcesses  int      `mapstructure:"min_processes" yaml:"min_processes"`
}

type TimingEvasionConfig struct {
	Enabled         bool     `mapstructure:"enabled" yaml:"enabled"`
	AdaptiveDelays  bool     `mapstructure:"adaptive_delays" yaml:"adaptive_delays"`
	ServiceMimicry  []string `mapstructure:"service_mimicry" yaml:"service_mimicry"`
	JitterPercentage float64  `mapstructure:"jitter_percentage" yaml:"jitter_percentage"`
}

// APTProfileConfig contains APT profile settings
type APTProfileConfig struct {
	Description      string `mapstructure:"description" yaml:"description"`
	TimingRange      [2]int `mapstructure:"timing_range" yaml:"timing_range"`
	SizeRange        [2]int `mapstructure:"size_range" yaml:"size_range"`
	CryptoPreference string `mapstructure:"crypto_preference" yaml:"crypto_preference"`
	Sophistication   string `mapstructure:"sophistication" yaml:"sophistication"`
}

// SIEMConfig contains SIEM integration settings
type SIEMConfig struct {
	Enabled           bool                   `mapstructure:"enabled" yaml:"enabled"`
	ConnectorType     string                 `mapstructure:"connector_type" yaml:"connector_type"`
	Endpoint          string                 `mapstructure:"endpoint" yaml:"endpoint"`
	Index             string                 `mapstructure:"index" yaml:"index"`
	SourceType        string                 `mapstructure:"sourcetype" yaml:"sourcetype"`
	APIToken          string                 `mapstructure:"api_token" yaml:"api_token"`
	RealTimeAlerting  bool                   `mapstructure:"real_time_alerting" yaml:"real_time_alerting"`
	AlertThresholds   map[string]interface{} `mapstructure:"alert_thresholds" yaml:"alert_thresholds"`
}

type SecurityConfig struct {
	AuditLogging         bool `mapstructure:"audit_logging" yaml:"audit_logging"`
	DataRetentionDays    int  `mapstructure:"data_retention_days" yaml:"data_retention_days"`
	EncryptionAtRest     bool `mapstructure:"encryption_at_rest" yaml:"encryption_at_rest"`
	SessionTimeout       int  `mapstructure:"session_timeout" yaml:"session_timeout"`
}

type ReportingConfig struct {
	Enabled          bool     `mapstructure:"enabled" yaml:"enabled"`
	OutputDir        string   `mapstructure:"output_dir" yaml:"output_dir"`
	Formats          []string `mapstructure:"formats" yaml:"formats"`
	RetentionDays    int      `mapstructure:"retention_days" yaml:"retention_days"`
	DashboardEnabled bool     `mapstructure:"dashboard_enabled" yaml:"dashboard_enabled"`
	DashboardPort    int      `mapstructure:"dashboard_port" yaml:"dashboard_port"`
	RefreshInterval  int      `mapstructure:"refresh_interval" yaml:"refresh_interval"`
}

// Load reads and validates the configuration
func Load() (*Config, error) {
	viper.SetConfigName("ping-007")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/ping-007")

	// Set defaults
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Framework defaults
	viper.SetDefault("framework.name", "PING-007")
	viper.SetDefault("framework.version", "2.0.0")
	viper.SetDefault("framework.environment", "production")
	viper.SetDefault("framework.debug_mode", false)
	viper.SetDefault("framework.log_level", "INFO")

	// Network defaults
	viper.SetDefault("network.authorized_targets", []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"203.0.113.0/24",
	})
	viper.SetDefault("network.forbidden_targets", []string{
		"0.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	})
	viper.SetDefault("network.default_interface", "eth0")
	viper.SetDefault("network.timeout", 30)
	viper.SetDefault("network.max_packet_size", 1500)

	// Evasion defaults
	viper.SetDefault("evasion.crypto_agility.enabled", true)
	viper.SetDefault("evasion.crypto_agility.algorithms", []string{"aes256", "chacha20", "custom_xor"})
	viper.SetDefault("evasion.crypto_agility.rotation_interval", 3600)
	viper.SetDefault("evasion.crypto_agility.default_algorithm", "aes256")

	viper.SetDefault("evasion.anti_sandbox.enabled", true)
	viper.SetDefault("evasion.anti_sandbox.strict_mode", true)
	viper.SetDefault("evasion.anti_sandbox.checks", []string{"uptime", "processes", "resources", "activity"})
	viper.SetDefault("evasion.anti_sandbox.min_uptime", 1800)
	viper.SetDefault("evasion.anti_sandbox.min_processes", 50)

	viper.SetDefault("evasion.timing_evasion.enabled", true)
	viper.SetDefault("evasion.timing_evasion.adaptive_delays", true)
	viper.SetDefault("evasion.timing_evasion.service_mimicry", []string{"windows_update", "ntp_sync", "antivirus"})
	viper.SetDefault("evasion.timing_evasion.jitter_percentage", 0.15)

	viper.SetDefault("evasion.traffic_analysis_resistance", true)
	viper.SetDefault("evasion.padding_sizes", []int{32, 48, 64, 128, 256, 512})
	viper.SetDefault("evasion.fake_data_injection_rate", 0.3)

	// APT profiles
	setAPTProfileDefaults()

	// Security defaults
	viper.SetDefault("security.audit_logging", true)
	viper.SetDefault("security.data_retention_days", 90)
	viper.SetDefault("security.encryption_at_rest", true)
	viper.SetDefault("security.session_timeout", 3600)
}

// setAPTProfileDefaults sets default APT profile configurations
func setAPTProfileDefaults() {
	viper.SetDefault("apt_profiles.lazarus.description", "Lazarus Group (North Korea)")
	viper.SetDefault("apt_profiles.lazarus.timing_range", [2]int{300, 3600})
	viper.SetDefault("apt_profiles.lazarus.size_range", [2]int{64, 1024})
	viper.SetDefault("apt_profiles.lazarus.crypto_preference", "aes256")
	viper.SetDefault("apt_profiles.lazarus.sophistication", "high")

	viper.SetDefault("apt_profiles.apt29.description", "Cozy Bear (Russia)")
	viper.SetDefault("apt_profiles.apt29.timing_range", [2]int{1800, 7200})
	viper.SetDefault("apt_profiles.apt29.size_range", [2]int{32, 512})
	viper.SetDefault("apt_profiles.apt29.crypto_preference", "chacha20")
	viper.SetDefault("apt_profiles.apt29.sophistication", "very_high")

	viper.SetDefault("apt_profiles.apt28.description", "Fancy Bear (Russia)")
	viper.SetDefault("apt_profiles.apt28.timing_range", [2]int{600, 1800})
	viper.SetDefault("apt_profiles.apt28.size_range", [2]int{128, 2048})
	viper.SetDefault("apt_profiles.apt28.crypto_preference", "custom_xor")
	viper.SetDefault("apt_profiles.apt28.sophistication", "high")

	viper.SetDefault("apt_profiles.equation.description", "Equation Group (NSA)")
	viper.SetDefault("apt_profiles.equation.timing_range", [2]int{86400, 259200})
	viper.SetDefault("apt_profiles.equation.size_range", [2]int{16, 64})
	viper.SetDefault("apt_profiles.equation.crypto_preference", "rsa_hybrid")
	viper.SetDefault("apt_profiles.equation.sophistication", "nation_state")
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	// Validate network ranges
	for _, target := range config.Network.AuthorizedTargets {
		if _, _, err := net.ParseCIDR(target); err != nil {
			return fmt.Errorf("invalid authorized target CIDR: %s", target)
		}
	}

	for _, target := range config.Network.ForbiddenTargets {
		if _, _, err := net.ParseCIDR(target); err != nil {
			return fmt.Errorf("invalid forbidden target CIDR: %s", target)
		}
	}

	// Validate timing and crypto settings
	if config.Evasion.CryptoAgility.RotationInterval < 300 {
		return fmt.Errorf("crypto rotation interval too short (minimum 300 seconds)")
	}

	if config.Evasion.AntiSandbox.MinUptime < 0 {
		return fmt.Errorf("minimum uptime cannot be negative")
	}

	// Validate APT profiles
	for name, profile := range config.APTProfiles {
		if profile.TimingRange[0] > profile.TimingRange[1] {
			return fmt.Errorf("invalid timing range for APT profile %s", name)
		}
		if profile.SizeRange[0] > profile.SizeRange[1] {
			return fmt.Errorf("invalid size range for APT profile %s", name)
		}
	}

	return nil
}

// ValidateTarget checks if a target is authorized
func (c *Config) ValidateTarget(target string) error {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		// Try to resolve hostname
		addrs, err := net.LookupIP(target)
		if err != nil {
			return fmt.Errorf("invalid target: cannot resolve %s", target)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("invalid target: no IP addresses found for %s", target)
		}
		targetIP = addrs[0]
	}

	// Check forbidden ranges first
	for _, forbidden := range c.Network.ForbiddenTargets {
		_, network, err := net.ParseCIDR(forbidden)
		if err != nil {
			continue
		}
		if network.Contains(targetIP) {
			return fmt.Errorf("target %s is in forbidden range %s", target, forbidden)
		}
	}

	// Check authorized ranges
	for _, authorized := range c.Network.AuthorizedTargets {
		_, network, err := net.ParseCIDR(authorized)
		if err != nil {
			continue
		}
		if network.Contains(targetIP) {
			return nil // Authorized
		}
	}

	return fmt.Errorf("target %s is not in any authorized range", target)
}

// GetAPTProfile returns the configuration for a specific APT profile
func (c *Config) GetAPTProfile(profile types.APTProfile) (*APTProfileConfig, error) {
	config, exists := c.APTProfiles[string(profile)]
	if !exists {
		return nil, fmt.Errorf("APT profile %s not found", profile)
	}
	return &config, nil
}

// EnsureDirectories creates necessary directories
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.Reporting.OutputDir,
		"logs",
		"config",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}