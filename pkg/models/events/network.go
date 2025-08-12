// Package events defines telemetry event structures for network monitoring
package events

import (
	"fmt"
	"time"

	"github.com/XXXXD-cation/Raptor-EDR/pkg/models/common"
)

// NetworkEvent represents comprehensive network connection events
type NetworkEvent struct {
	common.BaseEvent `bson:",inline"`
	
	// Process context
	PID         int32  `json:"pid" bson:"pid"`
	ProcessGUID string `json:"process_guid,omitempty" bson:"process_guid,omitempty"`
	ProcessName string `json:"process_name" bson:"process_name"`
	ProcessPath string `json:"process_path" bson:"process_path"`
	
	// User context
	User    string `json:"user" bson:"user"`
	UserSID string `json:"user_sid,omitempty" bson:"user_sid,omitempty"`
	UID     *int32 `json:"uid,omitempty" bson:"uid,omitempty"`
	
	// Network information
	Protocol    string `json:"protocol" bson:"protocol"` // tcp, udp, icmp
	LocalIP     string `json:"local_ip" bson:"local_ip"`
	LocalPort   int32  `json:"local_port" bson:"local_port"`
	RemoteIP    string `json:"remote_ip" bson:"remote_ip"`
	RemotePort  int32  `json:"remote_port" bson:"remote_port"`
	Direction   string `json:"direction" bson:"direction"` // inbound, outbound
	
	// DNS information (for DNS events)
	Domain      string   `json:"domain,omitempty" bson:"domain,omitempty"`
	QueryType   string   `json:"query_type,omitempty" bson:"query_type,omitempty"` // A, AAAA, CNAME, etc.
	ResponseCode string  `json:"response_code,omitempty" bson:"response_code,omitempty"`
	ResolvedIPs []string `json:"resolved_ips,omitempty" bson:"resolved_ips,omitempty"`
	
	// Connection metadata
	ConnectionState string         `json:"connection_state,omitempty" bson:"connection_state,omitempty"`
	BytesSent       int64          `json:"bytes_sent,omitempty" bson:"bytes_sent,omitempty"`
	BytesReceived   int64          `json:"bytes_received,omitempty" bson:"bytes_received,omitempty"`
	Duration        *time.Duration `json:"duration,omitempty" bson:"duration,omitempty"`
	
	// Geolocation and threat intelligence
	RemoteCountry string            `json:"remote_country,omitempty" bson:"remote_country,omitempty"`
	RemoteASN     string            `json:"remote_asn,omitempty" bson:"remote_asn,omitempty"`
	ThreatIntel   map[string]string `json:"threat_intel,omitempty" bson:"threat_intel,omitempty"`
}

// NewNetworkEvent creates a new network event with default values
func NewNetworkEvent(eventType common.EventType) *NetworkEvent {
	severity := common.SeverityLow
	
	// DNS queries are generally less suspicious than direct connections
	if eventType == common.NetworkDNSQuery || eventType == common.NetworkDNSResponse {
		severity = common.SeverityLow
	} else {
		severity = common.SeverityMedium
	}
	
	return &NetworkEvent{
		BaseEvent: common.BaseEvent{
			EventType: eventType,
			Timestamp: time.Now(),
			Severity:  severity,
		},
	}
}

// IsOutbound returns true if this is an outbound connection
func (n *NetworkEvent) IsOutbound() bool {
	return n.Direction == "outbound"
}

// IsInbound returns true if this is an inbound connection
func (n *NetworkEvent) IsInbound() bool {
	return n.Direction == "inbound"
}

// IsPrivateIP returns true if the remote IP is in a private range
func (n *NetworkEvent) IsPrivateIP() bool {
	// Simple check for common private IP ranges
	// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	if len(n.RemoteIP) >= 3 {
		if n.RemoteIP[:3] == "10." {
			return true
		}
		if n.RemoteIP[:4] == "172." && len(n.RemoteIP) >= 6 {
			// Check for 172.16-31.x.x
			return n.RemoteIP[4:6] >= "16" && n.RemoteIP[4:6] <= "31"
		}
		if len(n.RemoteIP) >= 8 && n.RemoteIP[:8] == "192.168." {
			return true
		}
		if n.RemoteIP == "127.0.0.1" || n.RemoteIP[:4] == "127." {
			return true
		}
	}
	return false
}

// IsCommonPort returns true if the port is a well-known service port
func (n *NetworkEvent) IsCommonPort() bool {
	commonPorts := map[int32]bool{
		21: true, 22: true, 23: true, 25: true, 53: true, 80: true, 110: true,
		143: true, 443: true, 993: true, 995: true, 1433: true, 3306: true,
		3389: true, 5432: true, 5985: true, 5986: true,
	}
	
	return commonPorts[n.RemotePort] || commonPorts[n.LocalPort]
}

// IsDNSEvent returns true if this is a DNS query or response event
func (n *NetworkEvent) IsDNSEvent() bool {
	return n.EventType == common.NetworkDNSQuery || n.EventType == common.NetworkDNSResponse
}

// HasSuspiciousDomain returns true if the domain appears suspicious
func (n *NetworkEvent) HasSuspiciousDomain() bool {
	if n.Domain == "" {
		return false
	}
	
	// Check for DGA-like characteristics (very basic heuristic)
	if len(n.Domain) > 20 {
		// Count consonant clusters and random-looking patterns
		vowels := "aeiou"
		consonantCount := 0
		for _, char := range n.Domain {
			isVowel := false
			for _, vowel := range vowels {
				if char == vowel {
					isVowel = true
					break
				}
			}
			if !isVowel && char != '.' && char != '-' {
				consonantCount++
			}
		}
		
		// If more than 70% consonants, might be suspicious
		if float64(consonantCount)/float64(len(n.Domain)) > 0.7 {
			return true
		}
	}
	
	return false
}

// GetConnectionString returns a string representation of the connection
func (n *NetworkEvent) GetConnectionString() string {
	if n.IsInbound() {
		return fmt.Sprintf("%s:%d -> %s:%d (%s)", n.RemoteIP, n.RemotePort, n.LocalIP, n.LocalPort, n.Protocol)
	}
	return fmt.Sprintf("%s:%d -> %s:%d (%s)", n.LocalIP, n.LocalPort, n.RemoteIP, n.RemotePort, n.Protocol)
} 