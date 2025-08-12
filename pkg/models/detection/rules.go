// Package detection defines detection rules and related structures
package detection

import (
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models/common"
)

// DetectionRule represents a security detection rule
type DetectionRule struct {
	ID          string            `json:"id" bson:"_id"`
	Name        string            `json:"name" bson:"name"`
	Description string            `json:"description" bson:"description"`
	Author      string            `json:"author,omitempty" bson:"author,omitempty"`
	Version     string            `json:"version" bson:"version"`
	
	// Rule classification
	Severity    common.Severity   `json:"severity" bson:"severity"`
	Category    string            `json:"category" bson:"category"` // malware, apt, lateral_movement, etc.
	RuleType    RuleType          `json:"rule_type" bson:"rule_type"`
	
	// MITRE ATT&CK mapping
	MITRETactics    []string      `json:"mitre_tactics" bson:"mitre_tactics"`
	MITRETechniques []string      `json:"mitre_techniques" bson:"mitre_techniques"`
	
	// Rule logic
	EventTypes  []common.EventType `json:"event_types" bson:"event_types"`
	Conditions  RuleConditions     `json:"conditions" bson:"conditions"`
	
	// Rule configuration
	Enabled   bool                `json:"enabled" bson:"enabled"`
	Actions   []AlertAction       `json:"actions" bson:"actions"`
	Threshold *ThresholdConfig    `json:"threshold,omitempty" bson:"threshold,omitempty"`
	
	// Metadata
	Tags           []string `json:"tags,omitempty" bson:"tags,omitempty"`
	References     []string `json:"references,omitempty" bson:"references,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty" bson:"false_positives,omitempty"`
	
	// Lifecycle
	CreatedAt     time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" bson:"updated_at"`
	LastTriggered *time.Time `json:"last_triggered,omitempty" bson:"last_triggered,omitempty"`
	TriggerCount  int64      `json:"trigger_count" bson:"trigger_count"`
}

// RuleType defines different types of detection rules
type RuleType string

const (
	RuleTypeSigma       RuleType = "sigma"        // Sigma rule format
	RuleTypeYARA        RuleType = "yara"         // YARA rule
	RuleTypeIOC         RuleType = "ioc"          // IOC matching
	RuleTypeBehavioral  RuleType = "behavioral"   // Behavioral analysis
	RuleTypeML          RuleType = "ml"           // Machine learning
	RuleTypeCorrelation RuleType = "correlation"  // Multi-event correlation
	RuleTypeCustom      RuleType = "custom"       // Custom Go logic
)

// RuleConditions defines the conditions for rule matching
type RuleConditions struct {
	// Simple field matching
	FieldMatches []FieldMatch `json:"field_matches,omitempty" bson:"field_matches,omitempty"`
	
	// Complex logic
	LogicalOperator LogicalOperator  `json:"logical_operator,omitempty" bson:"logical_operator,omitempty"`
	SubConditions   []RuleConditions `json:"sub_conditions,omitempty" bson:"sub_conditions,omitempty"`
	
	// Time-based conditions
	TimeWindow *time.Duration `json:"time_window,omitempty" bson:"time_window,omitempty"`
	
	// Frequency conditions
	MinOccurrences int `json:"min_occurrences,omitempty" bson:"min_occurrences,omitempty"`
	MaxOccurrences int `json:"max_occurrences,omitempty" bson:"max_occurrences,omitempty"`
	
	// Context conditions
	SameProcess bool `json:"same_process,omitempty" bson:"same_process,omitempty"`
	SameUser    bool `json:"same_user,omitempty" bson:"same_user,omitempty"`
	SameHost    bool `json:"same_host,omitempty" bson:"same_host,omitempty"`
	
	// Custom script/expression
	CustomLogic string `json:"custom_logic,omitempty" bson:"custom_logic,omitempty"`
}

// FieldMatch represents a condition on a specific field
type FieldMatch struct {
	Field         string        `json:"field" bson:"field"`
	Operator      MatchOperator `json:"operator" bson:"operator"`
	Value         interface{}   `json:"value" bson:"value"`
	CaseSensitive bool          `json:"case_sensitive,omitempty" bson:"case_sensitive,omitempty"`
}

// LogicalOperator for combining conditions
type LogicalOperator string

const (
	LogicalAND LogicalOperator = "and"
	LogicalOR  LogicalOperator = "or"
	LogicalNOT LogicalOperator = "not"
)

// MatchOperator for field matching
type MatchOperator string

const (
	OperatorEquals      MatchOperator = "equals"
	OperatorNotEquals   MatchOperator = "not_equals"
	OperatorContains    MatchOperator = "contains"
	OperatorNotContains MatchOperator = "not_contains"
	OperatorStartsWith  MatchOperator = "starts_with"
	OperatorEndsWith    MatchOperator = "ends_with"
	OperatorRegex       MatchOperator = "regex"
	OperatorGreater     MatchOperator = "greater"
	OperatorLess        MatchOperator = "less"
	OperatorIn          MatchOperator = "in"
	OperatorNotIn       MatchOperator = "not_in"
)

// ThresholdConfig defines threshold-based detection
type ThresholdConfig struct {
	Count      int           `json:"count" bson:"count"`
	TimeWindow time.Duration `json:"time_window" bson:"time_window"`
	GroupBy    []string      `json:"group_by,omitempty" bson:"group_by,omitempty"`
}

// AlertAction defines actions to take when a rule triggers
type AlertAction struct {
	Type       ActionType        `json:"type" bson:"type"`
	Parameters map[string]string `json:"parameters,omitempty" bson:"parameters,omitempty"`
	Enabled    bool              `json:"enabled" bson:"enabled"`
}

// ActionType defines different alert actions
type ActionType string

const (
	ActionAlert      ActionType = "alert"      // Create alert
	ActionEmail      ActionType = "email"      // Send email
	ActionWebhook    ActionType = "webhook"    // Call webhook
	ActionQuarantine ActionType = "quarantine" // Quarantine file/process
	ActionBlock      ActionType = "block"      // Block network/process
	ActionScript     ActionType = "script"     // Run custom script
	ActionSIEM       ActionType = "siem"       // Forward to SIEM
)

// NewDetectionRule creates a new detection rule with default values
func NewDetectionRule(name, description string) *DetectionRule {
	return &DetectionRule{
		Name:        name,
		Description: description,
		Version:     "1.0",
		Severity:    common.SeverityMedium,
		RuleType:    RuleTypeCustom,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Actions: []AlertAction{
			{
				Type:    ActionAlert,
				Enabled: true,
			},
		},
	}
}

// IsEnabled returns true if the rule is enabled
func (r *DetectionRule) IsEnabled() bool {
	return r.Enabled
}

// UpdateTriggerStats updates the trigger statistics
func (r *DetectionRule) UpdateTriggerStats() {
	now := time.Now()
	r.LastTriggered = &now
	r.TriggerCount++
	r.UpdatedAt = now
}

// MatchesEventType returns true if the rule applies to the given event type
func (r *DetectionRule) MatchesEventType(eventType common.EventType) bool {
	for _, et := range r.EventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}

// HasThreshold returns true if the rule has threshold configuration
func (r *DetectionRule) HasThreshold() bool {
	return r.Threshold != nil && r.Threshold.Count > 0
}

// GetAlertActions returns enabled alert actions
func (r *DetectionRule) GetAlertActions() []AlertAction {
	var enabled []AlertAction
	for _, action := range r.Actions {
		if action.Enabled {
			enabled = append(enabled, action)
		}
	}
	return enabled
} 