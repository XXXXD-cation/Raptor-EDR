// Package main implements the Raptor EDR agent executable
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/internal/agent/config"
	"github.com/XXXXD-cation/Raptor-EDR/internal/agent/sensor/common"
	"github.com/XXXXD-cation/Raptor-EDR/internal/agent/sensor/linux"
	"github.com/XXXXD-cation/Raptor-EDR/internal/agent/comms"
	"github.com/XXXXD-cation/Raptor-EDR/pkg/logger"
	"github.com/XXXXD-cation/Raptor-EDR/pkg/security"
	"github.com/rs/zerolog"
	"runtime"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	gitHash   = "unknown"
)

func main() {
	// Parse command line flags
	var (
		configFile  = flag.String("config", "", "Path to configuration file")
		versionFlag = flag.Bool("version", false, "Show version information")
		debugFlag   = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	// Show version and exit
	if *versionFlag {
		fmt.Printf("Raptor EDR Agent\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Git Hash: %s\n", gitHash)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if debug flag is set
	if *debugFlag {
		cfg.Logging.Level = "debug"
	}

	// Initialize logger
	loggerConfig := logger.Config{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		Output:     cfg.Logging.Output,
		TimeFormat: time.RFC3339,
	}
	if err := logger.Setup(loggerConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup logger: %v\n", err)
		os.Exit(1)
	}

	log := logger.GetLogger("agent")
	log.Info().
		Str("version", version).
		Str("build_time", buildTime).
		Str("git_hash", gitHash).
		Msg("Starting Raptor EDR Agent")

	// Generate agent ID if not provided
	if cfg.Agent.ID == "" {
		agentID, err := security.GenerateAgentID()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to generate agent ID")
		}
		cfg.Agent.ID = agentID
		log.Info().Str("agent_id", agentID).Msg("Generated new agent ID")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Configuration validation failed")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize and start the agent
	agent, err := NewAgent(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create agent")
	}

	// Start the agent
	if err := agent.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start agent")
	}

	log.Info().Msg("Agent started successfully")

	// Wait for shutdown signal
	<-sigChan
	log.Info().Msg("Shutdown signal received, stopping agent...")

	// Stop the agent gracefully
	if err := agent.Stop(); err != nil {
		log.Error().Err(err).Msg("Error during agent shutdown")
	}

	log.Info().Msg("Agent stopped")
}

// Agent represents the main agent instance
type Agent struct {
	config       *config.AgentConfig
	sensor       common.Sensor
	grpcClient   *comms.GRPCClient
	log          zerolog.Logger
	running      bool
	stopChan     chan struct{}
}

// NewAgent creates a new agent instance
func NewAgent(cfg *config.AgentConfig) (*Agent, error) {
	log := logger.GetLogger("agent")

	// Create platform-specific sensor
	var sensor common.Sensor
	switch runtime.GOOS {
	case "linux":
		sensor = linux.NewEBPFSensor()
	case "windows":
		// TODO: Implement Windows sensor
		return nil, fmt.Errorf("Windows sensor not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	// Create gRPC client
	clientConfig := comms.ClientConfig{
		ServerAddress: cfg.Server.Address,
		ServerPort:    cfg.Server.Port,
		UseTLS:        cfg.Server.UseTLS,
		Timeout:       cfg.Server.Timeout,
		RetryCount:    cfg.Server.RetryCount,
		RetryDelay:    cfg.Server.RetryDelay,
		KeepAlive:     cfg.Server.HealthCheck,
	}

	// Configure TLS if enabled
	if cfg.Server.UseTLS {
		tlsConfig, err := security.TLSConfig(
			cfg.Security.CertFile,
			cfg.Security.KeyFile,
			cfg.Security.CAFile,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		clientConfig.TLSConfig = tlsConfig
	}

	grpcClient := comms.NewGRPCClient(clientConfig)

	return &Agent{
		config:     cfg,
		sensor:     sensor,
		grpcClient: grpcClient,
		log:        log,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start starts the agent and all its components
func (a *Agent) Start(ctx context.Context) error {
	if a.running {
		return fmt.Errorf("agent is already running")
	}

	a.log.Info().Msg("Starting agent components...")

	// Connect to server
	if err := a.grpcClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	a.log.Info().Msg("Connected to server")

	// Register agent with server
	if err := a.registerWithServer(ctx); err != nil {
		return fmt.Errorf("failed to register with server: %w", err)
	}

	// Configure and start sensor
	sensorConfig := a.buildSensorConfig()
	if err := a.sensor.Initialize(sensorConfig); err != nil {
		return fmt.Errorf("failed to initialize sensor: %w", err)
	}

	if err := a.sensor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start sensor: %w", err)
	}
	a.log.Info().Msg("Sensor started")

	// Start event processing
	go a.processEvents(ctx)

	// Start heartbeat
	go a.sendHeartbeat(ctx)

	a.running = true
	return nil
}

// Stop stops the agent and all its components
func (a *Agent) Stop() error {
	if !a.running {
		return nil
	}

	a.log.Info().Msg("Stopping agent components...")

	// Signal all goroutines to stop
	close(a.stopChan)

	// Stop sensor
	if err := a.sensor.Stop(); err != nil {
		a.log.Error().Err(err).Msg("Error stopping sensor")
	}

	// Disconnect from server
	if err := a.grpcClient.Disconnect(); err != nil {
		a.log.Error().Err(err).Msg("Error disconnecting from server")
	}

	a.running = false
	return nil
}

// registerWithServer registers the agent with the server
func (a *Agent) registerWithServer(ctx context.Context) error {
	// TODO: Implement agent registration
	a.log.Info().Str("agent_id", a.config.Agent.ID).Msg("Registering with server")
	return nil
}

// buildSensorConfig creates sensor configuration from agent config
func (a *Agent) buildSensorConfig() common.SensorConfig {
	return common.SensorConfig{
		ProcessEvents:  a.config.Collection.ProcessEvents,
		FileEvents:     a.config.Collection.FileEvents,
		NetworkEvents:  a.config.Collection.NetworkEvents,
		RegistryEvents: a.config.Collection.RegistryEvents,
		AuthEvents:     a.config.Collection.AuthEvents,
		BufferSize:     a.config.Collection.BatchSize,
		FlushInterval:  a.config.Collection.BatchTimeout,
	}
}

// processEvents processes events from the sensor
func (a *Agent) processEvents(ctx context.Context) {
	a.log.Info().Msg("Starting event processing")
	
	eventChan := a.sensor.GetEvents()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopChan:
			return
		case event := <-eventChan:
			// TODO: Process and send events to server
			a.log.Debug().
				Str("event_id", event.ID).
				Str("event_type", string(event.EventType)).
				Msg("Received event")
		}
	}
}

// sendHeartbeat sends periodic heartbeats to the server
func (a *Agent) sendHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(a.config.Agent.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopChan:
			return
		case <-ticker.C:
			// TODO: Send heartbeat to server
			a.log.Debug().Msg("Sending heartbeat")
		}
	}
} 