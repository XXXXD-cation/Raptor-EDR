// Package events defines telemetry event structures for file system monitoring
package events

import (
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models/common"
)

// FileEvent represents comprehensive file system events
type FileEvent struct {
	common.BaseEvent `bson:",inline"`
	
	// File information
	Path         string `json:"path" bson:"path"`
	PreviousPath string `json:"previous_path,omitempty" bson:"previous_path,omitempty"` // For rename events
	Action       string `json:"action" bson:"action"`                                   // create, modify, delete, rename
	
	// Process context
	PID         int32  `json:"pid" bson:"pid"`
	ProcessGUID string `json:"process_guid,omitempty" bson:"process_guid,omitempty"`
	ProcessName string `json:"process_name" bson:"process_name"`
	ProcessPath string `json:"process_path" bson:"process_path"`
	
	// User context
	User    string `json:"user" bson:"user"`
	UserSID string `json:"user_sid,omitempty" bson:"user_sid,omitempty"`
	UID     *int32 `json:"uid,omitempty" bson:"uid,omitempty"`
	GID     *int32 `json:"gid,omitempty" bson:"gid,omitempty"`
	
	// File metadata
	Size   int64             `json:"size,omitempty" bson:"size,omitempty"`
	Hashes map[string]string `json:"hashes,omitempty" bson:"hashes,omitempty"`
	
	// Permission changes
	OldPermissions string `json:"old_permissions,omitempty" bson:"old_permissions,omitempty"`
	NewPermissions string `json:"new_permissions,omitempty" bson:"new_permissions,omitempty"`
	OldOwner       string `json:"old_owner,omitempty" bson:"old_owner,omitempty"`
	NewOwner       string `json:"new_owner,omitempty" bson:"new_owner,omitempty"`
	
	// File type and attributes
	FileType   string   `json:"file_type,omitempty" bson:"file_type,omitempty"`
	MimeType   string   `json:"mime_type,omitempty" bson:"mime_type,omitempty"`
	Attributes []string `json:"attributes,omitempty" bson:"attributes,omitempty"`
}

// NewFileEvent creates a new file event with default values
func NewFileEvent(action string) *FileEvent {
	eventType := common.FileCreate
	severity := common.SeverityLow
	
	switch action {
	case "create":
		eventType = common.FileCreate
	case "modify":
		eventType = common.FileModify
	case "delete":
		eventType = common.FileDelete
		severity = common.SeverityMedium // Deletions are more suspicious
	case "rename":
		eventType = common.FileRename
	}
	
	return &FileEvent{
		BaseEvent: common.BaseEvent{
			EventType: eventType,
			Timestamp: time.Now(),
			Severity:  severity,
		},
		Action: action,
	}
}

// IsExecutable returns true if the file appears to be executable
func (f *FileEvent) IsExecutable() bool {
	if f.FileType == "executable" {
		return true
	}
	
	// Check common executable extensions
	extensions := []string{".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
	for _, ext := range extensions {
		if len(f.Path) >= len(ext) && f.Path[len(f.Path)-len(ext):] == ext {
			return true
		}
	}
	
	// Check if it's in executable directories
	execDirs := []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "C:\\Windows\\System32\\", "C:\\Program Files\\"}
	for _, dir := range execDirs {
		if len(f.Path) >= len(dir) && f.Path[:len(dir)] == dir {
			return true
		}
	}
	
	return false
}

// IsSystemPath returns true if the file is in a system directory
func (f *FileEvent) IsSystemPath() bool {
	systemPaths := []string{
		"/etc/", "/usr/", "/var/", "/sys/", "/proc/",
		"C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
	}
	
	for _, path := range systemPaths {
		if len(f.Path) >= len(path) && f.Path[:len(path)] == path {
			return true
		}
	}
	
	return false
}

// IsTempPath returns true if the file is in a temporary directory
func (f *FileEvent) IsTempPath() bool {
	tempPaths := []string{
		"/tmp/", "/var/tmp/", "/dev/shm/",
		"C:\\Temp\\", "C:\\Windows\\Temp\\", "C:\\Users\\",
	}
	
	for _, path := range tempPaths {
		if len(f.Path) >= len(path) && f.Path[:len(path)] == path {
			return true
		}
	}
	
	return false
}

// GetMainHash returns the SHA256 hash if available, otherwise SHA1, then MD5
func (f *FileEvent) GetMainHash() string {
	if hash, exists := f.Hashes["sha256"]; exists && hash != "" {
		return hash
	}
	if hash, exists := f.Hashes["sha1"]; exists && hash != "" {
		return hash
	}
	if hash, exists := f.Hashes["md5"]; exists && hash != "" {
		return hash
	}
	return ""
}

// HasPermissionChange returns true if file permissions were changed
func (f *FileEvent) HasPermissionChange() bool {
	return f.OldPermissions != "" && f.NewPermissions != "" && f.OldPermissions != f.NewPermissions
}

// HasOwnershipChange returns true if file ownership was changed
func (f *FileEvent) HasOwnershipChange() bool {
	return f.OldOwner != "" && f.NewOwner != "" && f.OldOwner != f.NewOwner
} 