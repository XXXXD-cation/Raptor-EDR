// Package events defines telemetry event structures for process monitoring
package events

import (
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models/common"
)

// ProcessEvent represents comprehensive process creation/termination events
type ProcessEvent struct {
	common.BaseEvent `bson:",inline"`
	
	// Core process information
	PID         int32  `json:"pid" bson:"pid"`
	PPID        int32  `json:"ppid" bson:"ppid"`
	ProcessGUID string `json:"process_guid,omitempty" bson:"process_guid,omitempty"` // Unique across reboots
	ParentGUID  string `json:"parent_guid,omitempty" bson:"parent_guid,omitempty"`
	Name        string `json:"name" bson:"name"`
	Path        string `json:"path" bson:"path"`
	CommandLine string `json:"command_line" bson:"command_line"`
	
	// User context
	User    string `json:"user" bson:"user"`
	UserSID string `json:"user_sid,omitempty" bson:"user_sid,omitempty"` // Windows SID
	UID     *int32 `json:"uid,omitempty" bson:"uid,omitempty"`           // Linux UID
	GID     *int32 `json:"gid,omitempty" bson:"gid,omitempty"`           // Linux GID
	
	// Parent process information for attack chain analysis
	ParentName        string `json:"parent_name,omitempty" bson:"parent_name,omitempty"`
	ParentPath        string `json:"parent_path,omitempty" bson:"parent_path,omitempty"`
	ParentCommandLine string `json:"parent_command_line,omitempty" bson:"parent_command_line,omitempty"`
	
	// Security context (Windows)
	IntegrityLevel common.IntegrityLevel `json:"integrity_level,omitempty" bson:"integrity_level,omitempty"`
	TokenElevated  *bool                 `json:"token_elevated,omitempty" bson:"token_elevated,omitempty"`
	
	// File information and threat intelligence
	Hashes          map[string]string `json:"hashes,omitempty" bson:"hashes,omitempty"` // md5, sha1, sha256, imphash
	Signed          *bool             `json:"signed,omitempty" bson:"signed,omitempty"`
	Signature       string            `json:"signature,omitempty" bson:"signature,omitempty"`
	SignatureStatus string            `json:"signature_status,omitempty" bson:"signature_status,omitempty"`
	
	// Process termination (for exit events)
	ExitCode *int32     `json:"exit_code,omitempty" bson:"exit_code,omitempty"`
	ExitTime *time.Time `json:"exit_time,omitempty" bson:"exit_time,omitempty"`
	
	// Additional context
	WorkingDirectory string            `json:"working_directory,omitempty" bson:"working_directory,omitempty"`
	Environment      map[string]string `json:"environment,omitempty" bson:"environment,omitempty"`
}

// NewProcessEvent creates a new process event with default values
func NewProcessEvent() *ProcessEvent {
	return &ProcessEvent{
		BaseEvent: common.BaseEvent{
			EventType: common.ProcessCreate,
			Timestamp: time.Now(),
			Severity:  common.SeverityMedium,
		},
	}
}

// SetExitInfo sets exit information for process termination events
func (p *ProcessEvent) SetExitInfo(exitCode int32, exitTime time.Time) {
	p.EventType = common.ProcessExit
	p.ExitCode = &exitCode
	p.ExitTime = &exitTime
}

// IsElevated returns true if the process is running with elevated privileges
func (p *ProcessEvent) IsElevated() bool {
	if p.TokenElevated != nil && *p.TokenElevated {
		return true
	}
	return p.IntegrityLevel == common.IntegrityHigh || p.IntegrityLevel == common.IntegritySystem
}

// IsSigned returns true if the process executable is digitally signed
func (p *ProcessEvent) IsSigned() bool {
	return p.Signed != nil && *p.Signed
}

// GetMainHash returns the SHA256 hash if available, otherwise SHA1, then MD5
func (p *ProcessEvent) GetMainHash() string {
	if hash, exists := p.Hashes["sha256"]; exists && hash != "" {
		return hash
	}
	if hash, exists := p.Hashes["sha1"]; exists && hash != "" {
		return hash
	}
	if hash, exists := p.Hashes["md5"]; exists && hash != "" {
		return hash
	}
	return ""
}

// IsSystemProcess returns true if this appears to be a system process
func (p *ProcessEvent) IsSystemProcess() bool {
	return p.IntegrityLevel == common.IntegritySystem || 
		   p.User == "SYSTEM" || 
		   p.User == "root" ||
		   (p.UID != nil && *p.UID == 0)
} 