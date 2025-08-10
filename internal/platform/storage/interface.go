// Package storage defines interfaces for data persistence adapters
package storage

import (
	"context"
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models"
)

// EventRepository defines the interface for storing and retrieving telemetry events
type EventRepository interface {
	// Store persists events to the storage backend
	Store(ctx context.Context, events []models.Event) error
	
	// StoreBatch persists a batch of events with metadata
	StoreBatch(ctx context.Context, batch models.TelemetryBatch) error
	
	// Find retrieves events based on query criteria
	Find(ctx context.Context, query EventQuery) ([]models.Event, error)
	
	// FindByID retrieves a specific event by its ID
	FindByID(ctx context.Context, id string) (models.Event, error)
	
	// FindByAgent retrieves events from a specific agent
	FindByAgent(ctx context.Context, agentID string, limit int, offset int) ([]models.Event, error)
	
	// FindByTimeRange retrieves events within a time range
	FindByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]models.Event, error)
	
	// Count returns the total number of events matching the query
	Count(ctx context.Context, query EventQuery) (int64, error)
	
	// Delete removes events based on criteria (for data retention)
	Delete(ctx context.Context, query EventQuery) (int64, error)
	
	// CreateIndex creates an index for better query performance
	CreateIndex(ctx context.Context, fields []string) error
	
	// Health checks the health of the storage backend
	Health(ctx context.Context) error
	
	// Close closes the connection to the storage backend
	Close() error
}

// EventQuery represents query criteria for searching events
type EventQuery struct {
	// Event type filtering
	EventTypes []models.EventType `json:"event_types,omitempty"`
	
	// Agent filtering
	AgentIDs []string `json:"agent_ids,omitempty"`
	
	// Hostname filtering
	Hostnames []string `json:"hostnames,omitempty"`
	
	// Platform filtering
	Platforms []string `json:"platforms,omitempty"`
	
	// Time range filtering
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	
	// Field-specific filters
	ProcessName string            `json:"process_name,omitempty"`
	FilePath    string            `json:"file_path,omitempty"`
	NetworkIP   string            `json:"network_ip,omitempty"`
	UserName    string            `json:"user_name,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	
	// Query options
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
	SortBy     string `json:"sort_by,omitempty"`     // field to sort by
	SortOrder  string `json:"sort_order,omitempty"`  // asc, desc
	
	// Full-text search
	SearchText string `json:"search_text,omitempty"`
}

// MetadataRepository defines the interface for storing platform metadata
type MetadataRepository interface {
	// Agent management
	CreateAgent(ctx context.Context, agent AgentMetadata) error
	UpdateAgent(ctx context.Context, agentID string, agent AgentMetadata) error
	GetAgent(ctx context.Context, agentID string) (*AgentMetadata, error)
	ListAgents(ctx context.Context, limit, offset int) ([]AgentMetadata, error)
	DeleteAgent(ctx context.Context, agentID string) error
	
	// Detection rules
	CreateRule(ctx context.Context, rule DetectionRule) error
	UpdateRule(ctx context.Context, ruleID string, rule DetectionRule) error
	GetRule(ctx context.Context, ruleID string) (*DetectionRule, error)
	ListRules(ctx context.Context, enabled bool) ([]DetectionRule, error)
	DeleteRule(ctx context.Context, ruleID string) error
	
	// Alerts
	CreateAlert(ctx context.Context, alert Alert) error
	UpdateAlert(ctx context.Context, alertID string, alert Alert) error
	GetAlert(ctx context.Context, alertID string) (*Alert, error)
	ListAlerts(ctx context.Context, query AlertQuery) ([]Alert, error)
	
	// Health and cleanup
	Health(ctx context.Context) error
	Close() error
}

// AgentMetadata represents agent registration and status information
type AgentMetadata struct {
	ID           string            `json:"id" db:"id"`
	Hostname     string            `json:"hostname" db:"hostname"`
	Platform     string            `json:"platform" db:"platform"`
	Version      string            `json:"version" db:"version"`
	Capabilities []string          `json:"capabilities" db:"capabilities"`
	Tags         map[string]string `json:"tags" db:"tags"`
	Status       string            `json:"status" db:"status"` // online, offline, error
	LastSeen     time.Time         `json:"last_seen" db:"last_seen"`
	RegisteredAt time.Time         `json:"registered_at" db:"registered_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
}

// DetectionRule represents a security detection rule
type DetectionRule struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Severity    string            `json:"severity" db:"severity"` // low, medium, high, critical
	Enabled     bool              `json:"enabled" db:"enabled"`
	EventTypes  []string          `json:"event_types" db:"event_types"`
	Conditions  map[string]string `json:"conditions" db:"conditions"`
	Actions     []string          `json:"actions" db:"actions"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

// Alert represents a security alert generated by detection rules
type Alert struct {
	ID          string            `json:"id" db:"id"`
	RuleID      string            `json:"rule_id" db:"rule_id"`
	RuleName    string            `json:"rule_name" db:"rule_name"`
	AgentID     string            `json:"agent_id" db:"agent_id"`
	Hostname    string            `json:"hostname" db:"hostname"`
	Severity    string            `json:"severity" db:"severity"`
	Status      string            `json:"status" db:"status"` // open, investigating, resolved, false_positive
	EventIDs    []string          `json:"event_ids" db:"event_ids"`
	Context     map[string]string `json:"context" db:"context"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty" db:"resolved_at"`
}

// AlertQuery represents query criteria for searching alerts
type AlertQuery struct {
	RuleIDs   []string   `json:"rule_ids,omitempty"`
	AgentIDs  []string   `json:"agent_ids,omitempty"`
	Hostnames []string   `json:"hostnames,omitempty"`
	Severity  []string   `json:"severity,omitempty"`
	Status    []string   `json:"status,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// GraphRepository defines the interface for storing relationship data
type GraphRepository interface {
	// Store relationships between entities (processes, files, network connections)
	CreateRelationship(ctx context.Context, relationship Relationship) error
	
	// Find attack chains and related entities
	FindAttackChain(ctx context.Context, startEntity string, maxDepth int) ([]Relationship, error)
	
	// Find entities related to a specific entity
	FindRelated(ctx context.Context, entityID string, relationshipType string, depth int) ([]Entity, error)
	
	// Create entity nodes
	CreateEntity(ctx context.Context, entity Entity) error
	UpdateEntity(ctx context.Context, entityID string, entity Entity) error
	GetEntity(ctx context.Context, entityID string) (*Entity, error)
	
	// Query capabilities
	Query(ctx context.Context, cypherQuery string, params map[string]interface{}) ([]map[string]interface{}, error)
	
	// Health and cleanup
	Health(ctx context.Context) error
	Close() error
}

// Entity represents a node in the graph database
type Entity struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"` // process, file, network, user, etc.
	Properties map[string]string `json:"properties"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Relationship represents an edge in the graph database
type Relationship struct {
	ID         string            `json:"id"`
	FromID     string            `json:"from_id"`
	ToID       string            `json:"to_id"`
	Type       string            `json:"type"` // spawned, accessed, connected_to, etc.
	Properties map[string]string `json:"properties"`
	Weight     float64           `json:"weight,omitempty"` // Relationship strength/frequency
	CreatedAt  time.Time         `json:"created_at"`
} 