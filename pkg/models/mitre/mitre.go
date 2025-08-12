// Package models defines MITRE ATT&CK framework mappings and utilities
package models

// MITRETactic represents a MITRE ATT&CK tactic
type MITRETactic struct {
	ID          string `json:"id"`          // TA0001
	Name        string `json:"name"`        // Initial Access
	Description string `json:"description"`
	URL         string `json:"url"`
}

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID           string   `json:"id"`           // T1059
	SubTechnique string   `json:"sub_technique,omitempty"` // .001
	Name         string   `json:"name"`         // Command and Scripting Interpreter
	Description  string   `json:"description"`
	Tactics      []string `json:"tactics"`      // Execution
	Platforms    []string `json:"platforms"`    // Windows, Linux, macOS
	DataSources  []string `json:"data_sources"` // Process: Process Creation
	URL          string   `json:"url"`
}

// MITRE ATT&CK Tactics mapping
var MITRETactics = map[string]MITRETactic{
	"TA0001": {ID: "TA0001", Name: "Initial Access", Description: "The adversary is trying to get into your network."},
	"TA0002": {ID: "TA0002", Name: "Execution", Description: "The adversary is trying to run malicious code."},
	"TA0003": {ID: "TA0003", Name: "Persistence", Description: "The adversary is trying to maintain their foothold."},
	"TA0004": {ID: "TA0004", Name: "Privilege Escalation", Description: "The adversary is trying to gain higher-level permissions."},
	"TA0005": {ID: "TA0005", Name: "Defense Evasion", Description: "The adversary is trying to avoid being detected."},
	"TA0006": {ID: "TA0006", Name: "Credential Access", Description: "The adversary is trying to steal account names and passwords."},
	"TA0007": {ID: "TA0007", Name: "Discovery", Description: "The adversary is trying to figure out your environment."},
	"TA0008": {ID: "TA0008", Name: "Lateral Movement", Description: "The adversary is trying to move through your environment."},
	"TA0009": {ID: "TA0009", Name: "Collection", Description: "The adversary is trying to gather data of interest to their goal."},
	"TA0011": {ID: "TA0011", Name: "Command and Control", Description: "The adversary is trying to communicate with compromised systems."},
	"TA0010": {ID: "TA0010", Name: "Exfiltration", Description: "The adversary is trying to steal data."},
	"TA0040": {ID: "TA0040", Name: "Impact", Description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data."},
}

// Common MITRE ATT&CK Techniques mapping (subset for EDR focus)
var MITRETechniques = map[string]MITRETechnique{
	// Execution techniques
	"T1059": {
		ID: "T1059", Name: "Command and Scripting Interpreter",
		Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
		Tactics: []string{"Execution"}, Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Process: Process Creation", "Command: Command Execution"},
	},
	"T1059.001": {
		ID: "T1059", SubTechnique: ".001", Name: "PowerShell",
		Description: "Adversaries may abuse PowerShell commands and scripts for execution.",
		Tactics: []string{"Execution"}, Platforms: []string{"Windows"},
		DataSources: []string{"Process: Process Creation", "Script: Script Execution"},
	},
	"T1059.003": {
		ID: "T1059", SubTechnique: ".003", Name: "Windows Command Shell",
		Description: "Adversaries may abuse the Windows command shell for execution.",
		Tactics: []string{"Execution"}, Platforms: []string{"Windows"},
		DataSources: []string{"Process: Process Creation", "Command: Command Execution"},
	},
	"T1059.004": {
		ID: "T1059", SubTechnique: ".004", Name: "Unix Shell",
		Description: "Adversaries may abuse Unix shell commands and scripts for execution.",
		Tactics: []string{"Execution"}, Platforms: []string{"Linux", "macOS"},
		DataSources: []string{"Process: Process Creation", "Command: Command Execution"},
	},

	// Persistence techniques
	"T1053": {
		ID: "T1053", Name: "Scheduled Task/Job",
		Description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
		Tactics: []string{"Execution", "Persistence", "Privilege Escalation"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Scheduled Job: Scheduled Job Creation", "Process: Process Creation"},
	},
	"T1543": {
		ID: "T1543", Name: "Create or Modify System Process",
		Description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
		Tactics: []string{"Persistence", "Privilege Escalation"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Service: Service Creation", "Service: Service Modification"},
	},
	"T1547": {
		ID: "T1547", Name: "Boot or Logon Autostart Execution",
		Description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
		Tactics: []string{"Persistence", "Privilege Escalation"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Windows Registry: Windows Registry Key Creation", "Process: Process Creation"},
	},

	// Defense Evasion techniques
	"T1055": {
		ID: "T1055", Name: "Process Injection",
		Description: "Adversaries may inject code into processes in order to evade process-based defenses.",
		Tactics: []string{"Defense Evasion", "Privilege Escalation"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Process: Process Access", "Process: Process Modification"},
	},
	"T1070": {
		ID: "T1070", Name: "Indicator Removal",
		Description: "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.",
		Tactics: []string{"Defense Evasion"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"File: File Deletion", "Process: Process Creation"},
	},
	"T1112": {
		ID: "T1112", Name: "Modify Registry",
		Description: "Adversaries may interact with the Windows Registry to hide configuration information.",
		Tactics: []string{"Defense Evasion"},
		Platforms: []string{"Windows"},
		DataSources: []string{"Windows Registry: Windows Registry Key Modification", "Process: Process Creation"},
	},

	// Credential Access techniques
	"T1003": {
		ID: "T1003", Name: "OS Credential Dumping",
		Description: "Adversaries may attempt to dump credentials to obtain account login and credential material.",
		Tactics: []string{"Credential Access"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Process: Process Access", "Process: Process Creation"},
	},
	"T1003.001": {
		ID: "T1003", SubTechnique: ".001", Name: "LSASS Memory",
		Description: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
		Tactics: []string{"Credential Access"},
		Platforms: []string{"Windows"},
		DataSources: []string{"Process: Process Access"},
	},

	// Discovery techniques
	"T1057": {
		ID: "T1057", Name: "Process Discovery",
		Description: "Adversaries may attempt to get information about running processes on a system.",
		Tactics: []string{"Discovery"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Process: Process Creation", "Command: Command Execution"},
	},
	"T1083": {
		ID: "T1083", Name: "File and Directory Discovery",
		Description: "Adversaries may enumerate files and directories or may search in specific locations of a host or network share.",
		Tactics: []string{"Discovery"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Process: Process Creation", "Command: Command Execution"},
	},

	// Lateral Movement techniques
	"T1021": {
		ID: "T1021", Name: "Remote Services",
		Description: "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
		Tactics: []string{"Lateral Movement"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Logon Session: Logon Session Creation", "Network Traffic: Network Connection Creation"},
	},
	"T1021.001": {
		ID: "T1021", SubTechnique: ".001", Name: "Remote Desktop Protocol",
		Description: "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
		Tactics: []string{"Lateral Movement"},
		Platforms: []string{"Windows"},
		DataSources: []string{"Logon Session: Logon Session Creation", "Network Traffic: Network Connection Creation"},
	},

	// Command and Control techniques
	"T1071": {
		ID: "T1071", Name: "Application Layer Protocol",
		Description: "Adversaries may communicate using OSI application layer protocols to avoid detection.",
		Tactics: []string{"Command and Control"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Network Traffic: Network Traffic Content", "Network Traffic: Network Traffic Flow"},
	},
	"T1095": {
		ID: "T1095", Name: "Non-Application Layer Protocol",
		Description: "Adversaries may use a non-application layer protocol for communication between host and C2 server.",
		Tactics: []string{"Command and Control"},
		Platforms: []string{"Windows", "Linux", "macOS"},
		DataSources: []string{"Network Traffic: Network Traffic Flow"},
	},
}

// EventTypeToMITRE maps event types to relevant MITRE ATT&CK techniques
var EventTypeToMITRE = map[EventType][]string{
	ProcessCreate: {"T1059", "T1053", "T1543"},
	ProcessExit:   {"T1070"},
	
	FileCreate: {"T1547", "T1543"},
	FileModify: {"T1112", "T1547"},
	FileDelete: {"T1070"},
	
	NetworkConnect: {"T1071", "T1095", "T1021"},
	NetworkDNSQuery: {"T1071"},
	
	RegistryCreate: {"T1547", "T1112"},
	RegistryModify: {"T1112", "T1547"},
	RegistryDelete: {"T1070", "T1112"},
	
	ModuleLoad:      {"T1055"},
	ScriptExecution: {"T1059"},
	PowerShellBlock: {"T1059.001"},
	
	ServiceCreate: {"T1543"},
	ServiceModify: {"T1543"},
	ScheduledTask: {"T1053"},
	
	AuthLogin:        {"T1021"},
	AuthPrivEscalate: {"T1055", "T1053", "T1543"},
}

// GetTechniquesForEventType returns MITRE ATT&CK techniques relevant to an event type
func GetTechniquesForEventType(eventType EventType) []string {
	if techniques, exists := EventTypeToMITRE[eventType]; exists {
		return techniques
	}
	return []string{}
}

// GetTacticsForTechnique returns the tactics associated with a technique
func GetTacticsForTechnique(techniqueID string) []string {
	if technique, exists := MITRETechniques[techniqueID]; exists {
		return technique.Tactics
	}
	return []string{}
}

// GetTechniqueName returns the name of a technique
func GetTechniqueName(techniqueID string) string {
	if technique, exists := MITRETechniques[techniqueID]; exists {
		name := technique.Name
		if technique.SubTechnique != "" {
			name += " - " + technique.Name
		}
		return name
	}
	return techniqueID
}

// GetTacticName returns the name of a tactic
func GetTacticName(tacticID string) string {
	if tactic, exists := MITRETactics[tacticID]; exists {
		return tactic.Name
	}
	return tacticID
}

// EnrichEventWithMITRE adds MITRE ATT&CK context to an event
func EnrichEventWithMITRE(event Event) {
	techniques := GetTechniquesForEventType(event.GetEventType())
	
	// Get all tactics from techniques
	tacticSet := make(map[string]bool)
	for _, techniqueID := range techniques {
		tactics := GetTacticsForTechnique(techniqueID)
		for _, tactic := range tactics {
			tacticSet[tactic] = true
		}
	}
	
	// Convert set to slice
	var tactics []string
	for tactic := range tacticSet {
		tactics = append(tactics, tactic)
	}
	
	// This would need to be implemented differently based on the actual event struct
	// For now, this is a conceptual function
} 