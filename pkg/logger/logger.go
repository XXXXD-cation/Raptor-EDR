 // Package logger provides centralized logging setup for the Raptor-EDR platform
// Built on rs/zerolog for structured, high-performance logging
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds logger configuration
type Config struct {
	Level      string `json:"level" yaml:"level" mapstructure:"level"`
	Format     string `json:"format" yaml:"format" mapstructure:"format"` // json or console
	Output     string `json:"output" yaml:"output" mapstructure:"output"` // stdout, stderr, or file path
	TimeFormat string `json:"time_format" yaml:"time_format" mapstructure:"time_format"`
}

// DefaultConfig returns default logger configuration
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		TimeFormat: time.RFC3339,
	}
}

// Setup initializes the global logger with the provided configuration
func Setup(config Config) error {
	// Set log level
	level, err := zerolog.ParseLevel(config.Level)
	if err != nil {
		return err
	}
	zerolog.SetGlobalLevel(level)

	// Configure time format
	zerolog.TimeFieldFormat = config.TimeFormat

	// Configure output
	var writer io.Writer
	switch config.Output {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		writer = file
	}

	// Configure format
	if config.Format == "console" {
		writer = zerolog.ConsoleWriter{Out: writer}
	}

	// Set global logger
	log.Logger = zerolog.New(writer).With().Timestamp().Logger()

	return nil
}

// GetLogger returns a logger with component context
func GetLogger(component string) zerolog.Logger {
	return log.With().Str("component", component).Logger()
}