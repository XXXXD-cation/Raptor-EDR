// Package config manages agent configuration using viper
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// AgentConfig holds all agent configuration
type AgentConfig struct {
	Agent      AgentSettings      `mapstructure:"agent"`
	Server     ServerSettings     `mapstructure:"server"`
	Logging    LoggingSettings    `mapstructure:"logging"`
	Collection CollectionSettings `mapstructure:"collection"`
	Security   SecuritySettings   `mapstructure:"security"`
}

// AgentSettings contains agent-specific configuration
type AgentSettings struct {
	ID       string        `mapstructure:"id"`
	Name     string        `mapstructure:"name"`
	Version  string        `mapstructure:"version"`
	Interval time.Duration `mapstructure:"interval"`
	Tags     []string      `mapstructure:"tags"`
}

// ServerSettings contains server connection configuration
type ServerSettings struct {
	Address     string        `mapstructure:"address"`
	Port        int           `mapstructure:"port"`
	UseTLS      bool          `mapstructure:"use_tls"`
	Timeout     time.Duration `mapstructure:"timeout"`
	RetryCount  int           `mapstructure:"retry_count"`
	RetryDelay  time.Duration `mapstructure:"retry_delay"`
	HealthCheck time.Duration `mapstructure:"health_check"`
}

// LoggingSettings contains logging configuration
type LoggingSettings struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

// CollectionSettings contains data collection configuration
type CollectionSettings struct {
	ProcessEvents  bool     `mapstructure:"process_events"`
	FileEvents     bool     `mapstructure:"file_events"`
	NetworkEvents  bool     `mapstructure:"network_events"`
	RegistryEvents bool     `mapstructure:"registry_events"` // Windows only
	AuthEvents     bool     `mapstructure:"auth_events"`
	FilterRules    []string `mapstructure:"filter_rules"`
	BatchSize      int      `mapstructure:"batch_size"`
	BatchTimeout   time.Duration `mapstructure:"batch_timeout"`
}

// SecuritySettings contains security-related configuration
type SecuritySettings struct {
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	CAFile     string `mapstructure:"ca_file"`
	VerifyTLS  bool   `mapstructure:"verify_tls"`
	SignEvents bool   `mapstructure:"sign_events"`
}

// DefaultConfig returns default agent configuration
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		Agent: AgentSettings{
			Name:     "raptor-agent",
			Version:  "1.0.0",
			Interval: 30 * time.Second,
			Tags:     []string{},
		},
		Server: ServerSettings{
			Address:     "localhost",
			Port:        8443,
			UseTLS:      true,
			Timeout:     30 * time.Second,
			RetryCount:  3,
			RetryDelay:  5 * time.Second,
			HealthCheck: 60 * time.Second,
		},
		Logging: LoggingSettings{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		Collection: CollectionSettings{
			ProcessEvents:  true,
			FileEvents:     true,
			NetworkEvents:  true,
			RegistryEvents: true,
			AuthEvents:     true,
			FilterRules:    []string{},
			BatchSize:      100,
			BatchTimeout:   5 * time.Second,
		},
		Security: SecuritySettings{
			VerifyTLS:  true,
			SignEvents: true,
		},
	}
}

// Load loads configuration from file, environment variables, and command line flags
func Load(configFile string) (*AgentConfig, error) {
	config := DefaultConfig()

	// Set up viper
	viper.SetConfigName("agent")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/raptor-edr/")
	viper.AddConfigPath("$HOME/.raptor-edr")

	// Set environment variable prefix
	viper.SetEnvPrefix("EDR")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Read config file if specified
	if configFile != "" {
		viper.SetConfigFile(configFile)
	}

	// Read configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is acceptable, use defaults
	}

	// Unmarshal configuration
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}

// Validate validates the configuration
func (c *AgentConfig) Validate() error {
	if c.Agent.ID == "" {
		return fmt.Errorf("agent ID is required")
	}
	
	if c.Server.Address == "" {
		return fmt.Errorf("server address is required")
	}
	
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	
	if c.Server.UseTLS && (c.Security.CertFile == "" || c.Security.KeyFile == "") {
		return fmt.Errorf("TLS certificate and key files are required when TLS is enabled")
	}
	
	return nil
} 