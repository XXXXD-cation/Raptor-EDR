// Package models defines data structures for EDR telemetry events and shared types
package models

import (
	"time"
)

// EventType represents the type of telemetry event
type EventType string

const (
	// Process events
	ProcessCreate EventType = "process_create"
	ProcessExit   EventType = "process_exit"
	
	// File events
	FileCreate EventType = "file_create"
	FileModify EventType = "file_modify"
	FileDelete EventType = "file_delete"
	
	// Network events
	NetworkConnect EventType = "network_connect"
	NetworkListen  EventType = "network_listen"
	NetworkDNS     EventType = "network_dns"
	
	// Registry events (Windows)
	RegistryCreate EventType = "registry_create"
	RegistryModify EventType = "registry_modify"
	RegistryDelete EventType = "registry_delete"
	
	// Authentication events
	AuthLogin  EventType = "auth_login"
	AuthLogout EventType = "auth_logout"
	AuthFailed EventType = "auth_failed"
)

// BaseEvent contains common fields for all telemetry events
type BaseEvent struct {
	ID        string            `json:"id" bson:"_id"`
	Timestamp time.Time         `json:"timestamp" bson:"timestamp"`
	EventType EventType         `json:"event_type" bson:"event_type"`
	AgentID   string            `json:"agent_id" bson:"agent_id"`
	Hostname  string            `json:"hostname" bson:"hostname"`
	Platform  string            `json:"platform" bson:"platform"` // linux, windows, macos
	Tags      map[string]string `json:"tags,omitempty" bson:"tags,omitempty"`
}

// ProcessEvent represents process creation/termination events
type ProcessEvent struct {
	BaseEvent `bson:",inline"`
	
	PID        int32             `json:"pid" bson:"pid"`
	PPID       int32             `json:"ppid" bson:"ppid"`
	Name       string            `json:"name" bson:"name"`
	Path       string            `json:"path" bson:"path"`
	CommandLine string           `json:"command_line" bson:"command_line"`
	User       string            `json:"user" bson:"user"`
	ExitCode   *int32            `json:"exit_code,omitempty" bson:"exit_code,omitempty"`
	Hashes     map[string]string `json:"hashes,omitempty" bson:"hashes,omitempty"` // md5, sha1, sha256
}

// FileEvent represents file system events
type FileEvent struct {
	BaseEvent `bson:",inline"`
	
	Path       string            `json:"path" bson:"path"`
	Action     string            `json:"action" bson:"action"` // create, modify, delete, rename
	PID        int32             `json:"pid" bson:"pid"`
	ProcessName string           `json:"process_name" bson:"process_name"`
	User       string            `json:"user" bson:"user"`
	Hashes     map[string]string `json:"hashes,omitempty" bson:"hashes,omitempty"`
	Size       int64             `json:"size,omitempty" bson:"size,omitempty"`
}

// NetworkEvent represents network connection events
type NetworkEvent struct {
	BaseEvent `bson:",inline"`
	
	PID         int32  `json:"pid" bson:"pid"`
	ProcessName string `json:"process_name" bson:"process_name"`
	Protocol    string `json:"protocol" bson:"protocol"` // tcp, udp
	LocalIP     string `json:"local_ip" bson:"local_ip"`
	LocalPort   int32  `json:"local_port" bson:"local_port"`
	RemoteIP    string `json:"remote_ip" bson:"remote_ip"`
	RemotePort  int32  `json:"remote_port" bson:"remote_port"`
	Direction   string `json:"direction" bson:"direction"` // inbound, outbound
	Domain      string `json:"domain,omitempty" bson:"domain,omitempty"`
}

// RegistryEvent represents Windows registry events
type RegistryEvent struct {
	BaseEvent `bson:",inline"`
	
	PID         int32  `json:"pid" bson:"pid"`
	ProcessName string `json:"process_name" bson:"process_name"`
	KeyPath     string `json:"key_path" bson:"key_path"`
	ValueName   string `json:"value_name,omitempty" bson:"value_name,omitempty"`
	ValueData   string `json:"value_data,omitempty" bson:"value_data,omitempty"`
	ValueType   string `json:"value_type,omitempty" bson:"value_type,omitempty"`
	Action      string `json:"action" bson:"action"` // create, modify, delete
}

// AuthEvent represents authentication events
type AuthEvent struct {
	BaseEvent `bson:",inline"`
	
	Username    string `json:"username" bson:"username"`
	Domain      string `json:"domain,omitempty" bson:"domain,omitempty"`
	LogonType   string `json:"logon_type,omitempty" bson:"logon_type,omitempty"`
	SourceIP    string `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	Success     bool   `json:"success" bson:"success"`
	FailureCode string `json:"failure_code,omitempty" bson:"failure_code,omitempty"`
}

// TelemetryBatch represents a batch of events from an agent
type TelemetryBatch struct {
	AgentID   string      `json:"agent_id" bson:"agent_id"`
	Timestamp time.Time   `json:"timestamp" bson:"timestamp"`
	Events    []BaseEvent `json:"events" bson:"events"`
	Signature string      `json:"signature,omitempty" bson:"signature,omitempty"` // For integrity verification
} 