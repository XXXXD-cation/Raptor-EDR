// Package common defines shared types and interfaces for the EDR models
package common

import "time"

// EventType represents the type of telemetry event, aligned with MITRE ATT&CK techniques
type EventType string

const (
	// Process events - Core execution monitoring
	ProcessCreate EventType = "process_create"
	ProcessExit   EventType = "process_exit"
	
	// File system events - Persistence, impact, and defense evasion detection
	FileCreate           EventType = "file_create"
	FileModify           EventType = "file_modify"
	FileDelete           EventType = "file_delete"
	FileRename           EventType = "file_rename"
	FilePermissionChange EventType = "file_permission_change"
	FileOwnershipChange  EventType = "file_ownership_change"
	
	// Network events - Command & control, lateral movement detection
	NetworkConnect    EventType = "network_connect"
	NetworkListen     EventType = "network_listen"
	NetworkDNSQuery   EventType = "network_dns_query"
	NetworkDNSResponse EventType = "network_dns_response"
	
	// Authentication events - Initial access, lateral movement, privilege escalation
	AuthLogin        EventType = "auth_login"
	AuthLogout       EventType = "auth_logout"
	AuthFailed       EventType = "auth_failed"
	AuthPrivEscalate EventType = "auth_priv_escalate"
	
	// Registry events (Windows) - Persistence, defense evasion
	RegistryCreate EventType = "registry_create"
	RegistryModify EventType = "registry_modify"
	RegistryDelete EventType = "registry_delete"
	
	// Module/Library loading events - Defense evasion, privilege escalation
	ModuleLoad EventType = "module_load" // DLL/SO loading
	DriverLoad EventType = "driver_load" // Kernel driver loading
	
	// Script execution events - Execution, defense evasion
	ScriptExecution EventType = "script_execution"
	PowerShellBlock EventType = "powershell_block"
	
	// System configuration events - Persistence, defense evasion
	ServiceCreate EventType = "service_create"
	ServiceModify EventType = "service_modify"
	ScheduledTask EventType = "scheduled_task"
	WMIEvent      EventType = "wmi_event"
	
	// User/Group management events - Persistence, privilege escalation
	UserCreate        EventType = "user_create"
	UserModify        EventType = "user_modify"
	UserDelete        EventType = "user_delete"
	GroupCreate       EventType = "group_create"
	GroupModify       EventType = "group_modify"
	GroupDelete       EventType = "group_delete"
	GroupMemberAdd    EventType = "group_member_add"
	GroupMemberRemove EventType = "group_member_remove"
)

// Severity levels for events, rules and alerts
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Priority levels for investigations and tasks
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// LoginType represents different types of authentication methods
type LoginType string

const (
	LoginInteractive       LoginType = "interactive"        // Type 2 - Local console
	LoginNetwork           LoginType = "network"            // Type 3 - Network access
	LoginBatch             LoginType = "batch"              // Type 4 - Batch job
	LoginService           LoginType = "service"            // Type 5 - Service account
	LoginUnlock            LoginType = "unlock"             // Type 7 - Workstation unlock
	LoginNetworkCleartext  LoginType = "network_cleartext"  // Type 8 - Network with cleartext
	LoginRemoteInteractive LoginType = "remote_interactive" // Type 10 - RDP/Terminal Services
)

// IntegrityLevel represents Windows process integrity levels
type IntegrityLevel string

const (
	IntegrityUntrusted IntegrityLevel = "untrusted"
	IntegrityLow       IntegrityLevel = "low"
	IntegrityMedium    IntegrityLevel = "medium"
	IntegrityHigh      IntegrityLevel = "high"
	IntegritySystem    IntegrityLevel = "system"
)

// Event interface defines common methods for all telemetry events
type Event interface {
	GetID() string
	GetTimestamp() time.Time
	GetEventType() EventType
	GetAgentID() string
	GetHostname() string
	GetPlatform() string
	GetTags() map[string]string
	GetMITRETactics() []string
	GetMITRETechniques() []string
	GetSeverity() Severity
}

// BaseEvent contains common fields for all telemetry events
type BaseEvent struct {
	ID              string            `json:"id" bson:"_id"`
	Timestamp       time.Time         `json:"timestamp" bson:"timestamp"`
	EventType       EventType         `json:"event_type" bson:"event_type"`
	AgentID         string            `json:"agent_id" bson:"agent_id"`
	Hostname        string            `json:"hostname" bson:"hostname"`
	Platform        string            `json:"platform" bson:"platform"` // linux, windows, macos
	Tags            map[string]string `json:"tags,omitempty" bson:"tags,omitempty"`
	MITRETactics    []string          `json:"mitre_tactics,omitempty" bson:"mitre_tactics,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty" bson:"mitre_techniques,omitempty"`
	Severity        Severity          `json:"severity" bson:"severity"`
	ProcessedAt     time.Time         `json:"processed_at,omitempty" bson:"processed_at,omitempty"`
}

// Implement Event interface for BaseEvent
func (e BaseEvent) GetID() string                { return e.ID }
func (e BaseEvent) GetTimestamp() time.Time      { return e.Timestamp }
func (e BaseEvent) GetEventType() EventType      { return e.EventType }
func (e BaseEvent) GetAgentID() string           { return e.AgentID }
func (e BaseEvent) GetHostname() string          { return e.Hostname }
func (e BaseEvent) GetPlatform() string          { return e.Platform }
func (e BaseEvent) GetTags() map[string]string   { return e.Tags }
func (e BaseEvent) GetMITRETactics() []string    { return e.MITRETactics }
func (e BaseEvent) GetMITRETechniques() []string { return e.MITRETechniques }
func (e BaseEvent) GetSeverity() Severity        { return e.Severity }

// TelemetryBatch represents a batch of events from an agent
type TelemetryBatch struct {
	AgentID          string    `json:"agent_id" bson:"agent_id"`
	Timestamp        time.Time `json:"timestamp" bson:"timestamp"`
	Events           []Event   `json:"events" bson:"events"`
	Signature        string    `json:"signature,omitempty" bson:"signature,omitempty"` // For integrity verification
	BatchSequence    int64     `json:"batch_sequence" bson:"batch_sequence"`
	EventCount       int       `json:"event_count" bson:"event_count"`
	CompressedSize   int64     `json:"compressed_size,omitempty" bson:"compressed_size,omitempty"`
	UncompressedSize int64     `json:"uncompressed_size,omitempty" bson:"uncompressed_size,omitempty"`
} 