// Package comms handles gRPC communication between agent and server
package comms

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	agentv1 "github.com/raptor-edr/proto/agent/v1"
	"github.com/raptor-edr/pkg/models"
)

// GRPCClient handles gRPC communication with the server
type GRPCClient struct {
	config     ClientConfig
	conn       *grpc.ClientConn
	client     agentv1.AgentServiceClient
	connected  bool
	mu         sync.RWMutex
	
	// Streaming connections
	telemetryStream agentv1.AgentService_SendTelemetryClient
	streamMu        sync.Mutex
}

// ClientConfig holds gRPC client configuration
type ClientConfig struct {
	ServerAddress string
	ServerPort    int
	UseTLS        bool
	TLSConfig     *tls.Config
	Timeout       time.Duration
	RetryCount    int
	RetryDelay    time.Duration
	KeepAlive     time.Duration
}

// NewGRPCClient creates a new gRPC client
func NewGRPCClient(config ClientConfig) *GRPCClient {
	return &GRPCClient{
		config:    config,
		connected: false,
	}
}

// Connect establishes connection to the server
func (c *GRPCClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Build connection options
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.config.KeepAlive,
			Timeout:             c.config.Timeout,
			PermitWithoutStream: true,
		}),
	}

	// Configure TLS
	if c.config.UseTLS {
		if c.config.TLSConfig != nil {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(c.config.TLSConfig)))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				ServerName: c.config.ServerAddress,
			})))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// Connect with retry logic
	var conn *grpc.ClientConn
	var err error
	
	for i := 0; i < c.config.RetryCount; i++ {
		target := fmt.Sprintf("%s:%d", c.config.ServerAddress, c.config.ServerPort)
		
		dialCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
		conn, err = grpc.DialContext(dialCtx, target, opts...)
		cancel()
		
		if err == nil {
			break
		}
		
		if i < c.config.RetryCount-1 {
			time.Sleep(c.config.RetryDelay)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	c.conn = conn
	c.client = agentv1.NewAgentServiceClient(conn)
	c.connected = true

	return nil
}

// Disconnect closes the connection to the server
func (c *GRPCClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// Close telemetry stream if active
	c.streamMu.Lock()
	if c.telemetryStream != nil {
		c.telemetryStream.CloseSend()
		c.telemetryStream = nil
	}
	c.streamMu.Unlock()

	// Close connection
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		c.connected = false
		return err
	}

	return nil
}

// IsConnected returns the connection status
func (c *GRPCClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// RegisterAgent registers the agent with the server
func (c *GRPCClient) RegisterAgent(ctx context.Context, req *agentv1.RegisterAgentRequest) (*agentv1.RegisterAgentResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	return client.RegisterAgent(ctx, req)
}

// SendTelemetryBatch sends a batch of telemetry data to the server
func (c *GRPCClient) SendTelemetryBatch(ctx context.Context, batch *agentv1.TelemetryBatch) error {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()

	// Create stream if it doesn't exist
	if c.telemetryStream == nil {
		c.mu.RLock()
		client := c.client
		c.mu.RUnlock()

		if client == nil {
			return fmt.Errorf("client not connected")
		}

		stream, err := client.SendTelemetry(ctx)
		if err != nil {
			return fmt.Errorf("failed to create telemetry stream: %w", err)
		}
		c.telemetryStream = stream
	}

	// Send the batch
	if err := c.telemetryStream.Send(batch); err != nil {
		// Stream is broken, reset it
		c.telemetryStream = nil
		return fmt.Errorf("failed to send telemetry batch: %w", err)
	}

	return nil
}

// GetTasks retrieves tasks assigned to the agent
func (c *GRPCClient) GetTasks(ctx context.Context, req *agentv1.GetTasksRequest) (*agentv1.GetTasksResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	return client.GetTasks(ctx, req)
}

// SendTaskResult sends task execution results to the server
func (c *GRPCClient) SendTaskResult(ctx context.Context, result *agentv1.TaskResult) (*agentv1.TaskResultResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	return client.SendTaskResult(ctx, result)
}

// SendHeartbeat sends a heartbeat to the server
func (c *GRPCClient) SendHeartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	return client.Heartbeat(ctx, req)
}

// ConvertEventToProto converts internal event models to protobuf format
func ConvertEventToProto(event models.BaseEvent) *agentv1.Event {
	protoEvent := &agentv1.Event{
		Id:        event.ID,
		EventType: string(event.EventType),
		AgentId:   event.AgentID,
		Hostname:  event.Hostname,
		Platform:  event.Platform,
		Tags:      event.Tags,
	}

	// Convert timestamp
	if !event.Timestamp.IsZero() {
		protoEvent.Timestamp = timestamppb.New(event.Timestamp)
	}

	// Convert event-specific data based on type
	switch event.EventType {
	case models.ProcessCreate, models.ProcessExit:
		if processEvent, ok := event.(models.ProcessEvent); ok {
			protoEvent.EventData = &agentv1.Event_ProcessEvent{
				ProcessEvent: &agentv1.ProcessEvent{
					Pid:         processEvent.PID,
					Ppid:        processEvent.PPID,
					Name:        processEvent.Name,
					Path:        processEvent.Path,
					CommandLine: processEvent.CommandLine,
					User:        processEvent.User,
					Hashes:      processEvent.Hashes,
				},
			}
			if processEvent.ExitCode != nil {
				protoEvent.GetProcessEvent().ExitCode = *processEvent.ExitCode
			}
		}
	case models.FileCreate, models.FileModify, models.FileDelete:
		if fileEvent, ok := event.(models.FileEvent); ok {
			protoEvent.EventData = &agentv1.Event_FileEvent{
				FileEvent: &agentv1.FileEvent{
					Path:        fileEvent.Path,
					Action:      fileEvent.Action,
					Pid:         fileEvent.PID,
					ProcessName: fileEvent.ProcessName,
					User:        fileEvent.User,
					Hashes:      fileEvent.Hashes,
					Size:        fileEvent.Size,
				},
			}
		}
	case models.NetworkConnect, models.NetworkListen, models.NetworkDNS:
		if networkEvent, ok := event.(models.NetworkEvent); ok {
			protoEvent.EventData = &agentv1.Event_NetworkEvent{
				NetworkEvent: &agentv1.NetworkEvent{
					Pid:         networkEvent.PID,
					ProcessName: networkEvent.ProcessName,
					Protocol:    networkEvent.Protocol,
					LocalIp:     networkEvent.LocalIP,
					LocalPort:   networkEvent.LocalPort,
					RemoteIp:    networkEvent.RemoteIP,
					RemotePort:  networkEvent.RemotePort,
					Direction:   networkEvent.Direction,
					Domain:      networkEvent.Domain,
				},
			}
		}
	}

	return protoEvent
} 