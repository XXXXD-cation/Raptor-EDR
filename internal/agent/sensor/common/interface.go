// Package common defines interfaces and types shared across platform-specific sensors
package common

import (
	"context"
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models"
)

// Sensor defines the interface that all platform-specific sensors must implement
type Sensor interface {
	// Initialize sets up the sensor with the provided configuration
	Initialize(config SensorConfig) error

	// Start begins data collection
	Start(ctx context.Context) error

	// Stop stops data collection and cleans up resources
	Stop() error

	// GetEvents returns a channel of collected events
	GetEvents() <-chan models.Event

	// GetStats returns sensor statistics
	GetStats() SensorStats

	// SetFilters applies filtering rules to reduce noise
	SetFilters(filters []FilterRule) error
}

// SensorConfig holds configuration for sensors
type SensorConfig struct {
	// Event types to collect
	ProcessEvents  bool `json:"process_events"`
	FileEvents     bool `json:"file_events"`
	NetworkEvents  bool `json:"network_events"`
	RegistryEvents bool `json:"registry_events"` // Windows only
	AuthEvents     bool `json:"auth_events"`

	// Collection settings
	BufferSize    int           `json:"buffer_size"`
	FlushInterval time.Duration `json:"flush_interval"`
	
	// Filtering
	EnableFiltering bool         `json:"enable_filtering"`
	FilterRules     []FilterRule `json:"filter_rules"`
	
	// Platform-specific settings
	LinuxConfig   *LinuxSensorConfig   `json:"linux_config,omitempty"`
	WindowsConfig *WindowsSensorConfig `json:"windows_config,omitempty"`
}

// LinuxSensorConfig contains Linux-specific sensor configuration
type LinuxSensorConfig struct {
	UseEBPF        bool     `json:"use_ebpf"`
	EBPFObjectPath string   `json:"ebpf_object_path"`
	ProcfsPath     string   `json:"procfs_path"`
	SysfsPath      string   `json:"sysfs_path"`
	MonitorPaths   []string `json:"monitor_paths"`
}

// WindowsSensorConfig contains Windows-specific sensor configuration
type WindowsSensorConfig struct {
	UseETW           bool     `json:"use_etw"`
	ETWProviders     []string `json:"etw_providers"`
	UseWMI           bool     `json:"use_wmi"`
	RegistryKeys     []string `json:"registry_keys"`
	MonitorPaths     []string `json:"monitor_paths"`
	CollectPerfData  bool     `json:"collect_perf_data"`
}

// FilterRule defines a rule for filtering events
type FilterRule struct {
	Name      string            `json:"name"`
	EventType models.EventType  `json:"event_type"`
	Action    FilterAction      `json:"action"` // allow, deny
	Condition FilterCondition   `json:"condition"`
	Fields    map[string]string `json:"fields"`
}

// FilterAction defines the action to take when a filter rule matches
type FilterAction string

const (
	FilterActionAllow FilterAction = "allow"
	FilterActionDeny  FilterAction = "deny"
)

// FilterCondition defines the condition logic for filter rules
type FilterCondition string

const (
	FilterConditionEquals    FilterCondition = "equals"
	FilterConditionContains  FilterCondition = "contains"
	FilterConditionStartsWith FilterCondition = "starts_with"
	FilterConditionEndsWith   FilterCondition = "ends_with"
	FilterConditionRegex     FilterCondition = "regex"
)

// SensorStats contains statistics about sensor performance
type SensorStats struct {
	EventsCollected   uint64        `json:"events_collected"`
	EventsFiltered    uint64        `json:"events_filtered"`
	EventsDropped     uint64        `json:"events_dropped"`
	BytesCollected    uint64        `json:"bytes_collected"`
	CollectionRate    float64       `json:"collection_rate"` // events per second
	LastEventTime     time.Time     `json:"last_event_time"`
	UptimeSeconds     uint64        `json:"uptime_seconds"`
	MemoryUsageMB     float64       `json:"memory_usage_mb"`
	CPUUsagePercent   float64       `json:"cpu_usage_percent"`
	ErrorCount        uint64        `json:"error_count"`
	LastError         string        `json:"last_error,omitempty"`
	PlatformSpecific  interface{}   `json:"platform_specific,omitempty"`
}

// SensorManager manages multiple sensors and coordinates their operation
type SensorManager interface {
	// AddSensor adds a sensor to the manager
	AddSensor(name string, sensor Sensor) error

	// RemoveSensor removes a sensor from the manager
	RemoveSensor(name string) error

	// StartAll starts all registered sensors
	StartAll(ctx context.Context) error

	// StopAll stops all registered sensors
	StopAll() error

	// GetAggregatedEvents returns a channel with events from all sensors
	GetAggregatedEvents() <-chan models.Event

	// GetAggregatedStats returns combined statistics from all sensors
	GetAggregatedStats() map[string]SensorStats
} 