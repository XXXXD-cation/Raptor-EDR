 // Package enrichment defines threat intelligence and data enrichment structures
package enrichment

import "time"

// ThreatIntelData represents threat intelligence information
type ThreatIntelData struct {
	IOCMatches   []IOCMatch `json:"ioc_matches,omitempty" bson:"ioc_matches,omitempty"`
	ThreatActors []string   `json:"threat_actors,omitempty" bson:"threat_actors,omitempty"`
	Campaigns    []string   `json:"campaigns,omitempty" bson:"campaigns,omitempty"`
	Families     []string   `json:"families,omitempty" bson:"families,omitempty"`
	Confidence   int        `json:"confidence,omitempty" bson:"confidence,omitempty"` // 0-100
	LastUpdated  time.Time  `json:"last_updated,omitempty" bson:"last_updated,omitempty"`
}

// IOCMatch represents a matched indicator of compromise
type IOCMatch struct {
	Type       string    `json:"type" bson:"type"` // hash, ip, domain, url, email
	Value      string    `json:"value" bson:"value"`
	Source     string    `json:"source" bson:"source"`
	Confidence int       `json:"confidence" bson:"confidence"`
	Tags       []string  `json:"tags,omitempty" bson:"tags,omitempty"`
	FirstSeen  time.Time `json:"first_seen,omitempty" bson:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty" bson:"last_seen,omitempty"`
}

// GeolocationData represents geolocation information for IP addresses
type GeolocationData struct {
	Country      string  `json:"country,omitempty" bson:"country,omitempty"`
	Region       string  `json:"region,omitempty" bson:"region,omitempty"`
	City         string  `json:"city,omitempty" bson:"city,omitempty"`
	Latitude     float64 `json:"latitude,omitempty" bson:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty" bson:"longitude,omitempty"`
	ASN          string  `json:"asn,omitempty" bson:"asn,omitempty"`
	Organization string  `json:"organization,omitempty" bson:"organization,omitempty"`
	ISP          string  `json:"isp,omitempty" bson:"isp,omitempty"`
	Timezone     string  `json:"timezone,omitempty" bson:"timezone,omitempty"`
}

// AssetInfo represents information about the asset/host
type AssetInfo struct {
	AssetID     string   `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	AssetType   string   `json:"asset_type,omitempty" bson:"asset_type,omitempty"` // workstation, server, mobile
	Department  string   `json:"department,omitempty" bson:"department,omitempty"`
	Owner       string   `json:"owner,omitempty" bson:"owner,omitempty"`
	Location    string   `json:"location,omitempty" bson:"location,omitempty"`
	Criticality string   `json:"criticality,omitempty" bson:"criticality,omitempty"` // low, medium, high, critical
	Environment string   `json:"environment,omitempty" bson:"environment,omitempty"` // dev, test, prod
	Tags        []string `json:"tags,omitempty" bson:"tags,omitempty"`
	
	// System information
	OS          string `json:"os,omitempty" bson:"os,omitempty"`
	OSVersion   string `json:"os_version,omitempty" bson:"os_version,omitempty"`
	Architecture string `json:"architecture,omitempty" bson:"architecture,omitempty"`
	
	// Network information
	IPAddresses []string `json:"ip_addresses,omitempty" bson:"ip_addresses,omitempty"`
	MACAddress  string   `json:"mac_address,omitempty" bson:"mac_address,omitempty"`
	Domain      string   `json:"domain,omitempty" bson:"domain,omitempty"`
}

// EnrichedEvent represents an event with additional context and threat intelligence
type EnrichedEvent struct {
	EventID         string              `json:"event_id" bson:"event_id"`
	ThreatIntel     ThreatIntelData     `json:"threat_intel,omitempty" bson:"threat_intel,omitempty"`
	Geolocation     GeolocationData     `json:"geolocation,omitempty" bson:"geolocation,omitempty"`
	AssetInfo       AssetInfo           `json:"asset_info,omitempty" bson:"asset_info,omitempty"`
	ProcessedAt     time.Time           `json:"processed_at" bson:"processed_at"`
	EnrichmentRules []string            `json:"enrichment_rules,omitempty" bson:"enrichment_rules,omitempty"`
	Confidence      int                 `json:"confidence" bson:"confidence"` // Overall confidence 0-100
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	ID          string    `json:"id" bson:"_id"`
	Name        string    `json:"name" bson:"name"`
	Description string    `json:"description" bson:"description"`
	Source      string    `json:"source" bson:"source"`
	Type        FeedType  `json:"type" bson:"type"`
	Format      string    `json:"format" bson:"format"` // json, xml, csv, stix
	URL         string    `json:"url,omitempty" bson:"url,omitempty"`
	APIKey      string    `json:"api_key,omitempty" bson:"api_key,omitempty"`
	Enabled     bool      `json:"enabled" bson:"enabled"`
	
	// Update configuration
	UpdateInterval time.Duration `json:"update_interval" bson:"update_interval"`
	LastUpdated    time.Time     `json:"last_updated" bson:"last_updated"`
	NextUpdate     time.Time     `json:"next_update" bson:"next_update"`
	
	// Statistics
	TotalIndicators   int       `json:"total_indicators" bson:"total_indicators"`
	ActiveIndicators  int       `json:"active_indicators" bson:"active_indicators"`
	LastSuccessUpdate time.Time `json:"last_success_update" bson:"last_success_update"`
	LastError         string    `json:"last_error,omitempty" bson:"last_error,omitempty"`
}

// FeedType represents different types of threat intelligence feeds
type FeedType string

const (
	FeedTypeIOC       FeedType = "ioc"        // Indicators of Compromise
	FeedTypeReputation FeedType = "reputation" // IP/Domain reputation
	FeedTypeSignature FeedType = "signature"  // Detection signatures
	FeedTypeTTP       FeedType = "ttp"        // Tactics, Techniques, Procedures
	FeedTypeActor     FeedType = "actor"      // Threat actor information
	FeedTypeCampaign  FeedType = "campaign"   // Campaign information
)

// Indicator represents a threat indicator
type Indicator struct {
	ID          string           `json:"id" bson:"_id"`
	Type        IndicatorType    `json:"type" bson:"type"`
	Value       string           `json:"value" bson:"value"`
	Description string           `json:"description,omitempty" bson:"description,omitempty"`
	
	// Classification
	Confidence  int      `json:"confidence" bson:"confidence"` // 0-100
	Severity    string   `json:"severity" bson:"severity"`     // low, medium, high, critical
	TLP         string   `json:"tlp" bson:"tlp"`               // Traffic Light Protocol
	Tags        []string `json:"tags,omitempty" bson:"tags,omitempty"`
	
	// Attribution
	ThreatActors []string `json:"threat_actors,omitempty" bson:"threat_actors,omitempty"`
	Campaigns    []string `json:"campaigns,omitempty" bson:"campaigns,omitempty"`
	Families     []string `json:"families,omitempty" bson:"families,omitempty"`
	
	// Temporal information
	FirstSeen time.Time  `json:"first_seen" bson:"first_seen"`
	LastSeen  time.Time  `json:"last_seen" bson:"last_seen"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" bson:"expires_at,omitempty"`
	
	// Source information
	Sources []string `json:"sources" bson:"sources"`
	FeedID  string   `json:"feed_id" bson:"feed_id"`
	
	// Context
	Context map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
}

// IndicatorType represents different types of indicators
type IndicatorType string

const (
	IndicatorTypeHash     IndicatorType = "hash"     // File hashes
	IndicatorTypeIP       IndicatorType = "ip"       // IP addresses
	IndicatorTypeDomain   IndicatorType = "domain"   // Domain names
	IndicatorTypeURL      IndicatorType = "url"      // URLs
	IndicatorTypeEmail    IndicatorType = "email"    // Email addresses
	IndicatorTypeRegistry IndicatorType = "registry" // Registry keys/values
	IndicatorTypeMutex    IndicatorType = "mutex"    // Mutex names
	IndicatorTypeUserAgent IndicatorType = "user_agent" // User agent strings
)

// NewIOCMatch creates a new IOC match
func NewIOCMatch(iocType, value, source string, confidence int) IOCMatch {
	return IOCMatch{
		Type:       iocType,
		Value:      value,
		Source:     source,
		Confidence: confidence,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}
}

// IsExpired returns true if the indicator has expired
func (i *Indicator) IsExpired() bool {
	return i.ExpiresAt != nil && time.Now().After(*i.ExpiresAt)
}

// IsActive returns true if the indicator is still active
func (i *Indicator) IsActive() bool {
	return !i.IsExpired()
}

// GetAgeInDays returns the age of the indicator in days
func (i *Indicator) GetAgeInDays() int {
	return int(time.Since(i.FirstSeen).Hours() / 24)
}

// HasHighConfidence returns true if the indicator has high confidence
func (i *Indicator) HasHighConfidence() bool {
	return i.Confidence >= 80
}

// MatchesValue returns true if the indicator matches the given value
func (i *Indicator) MatchesValue(value string) bool {
	return i.Value == value
}

// AddSource adds a source to the indicator if not already present
func (i *Indicator) AddSource(source string) {
	for _, s := range i.Sources {
		if s == source {
			return
		}
	}
	i.Sources = append(i.Sources, source)
}

// UpdateLastSeen updates the last seen timestamp
func (i *Indicator) UpdateLastSeen() {
	i.LastSeen = time.Now()
}