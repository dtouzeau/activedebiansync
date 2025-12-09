package database

import (
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SecurityRuleType defines the type of security rule
type SecurityRuleType string

const (
	RuleTypeAllow SecurityRuleType = "allow"
	RuleTypeDeny  SecurityRuleType = "deny"
	RuleTypeLimit SecurityRuleType = "limit" // Bandwidth limit
)

// SecurityRule represents an access control rule
type SecurityRule struct {
	ID              int64            `json:"id"`
	Name            string           `json:"name"`
	Type            SecurityRuleType `json:"type"`              // allow, deny, limit
	Priority        int              `json:"priority"`          // Higher priority = evaluated first
	Enabled         bool             `json:"enabled"`           // Rule is active
	IPAddress       string           `json:"ip_address"`        // Single IP, CIDR, or empty for any
	UserAgentMatch  string           `json:"user_agent_match"`  // Regex pattern or empty for any
	BandwidthLimit  int64            `json:"bandwidth_limit"`   // Bytes per second (0 = unlimited)
	ApplyToHTTP     bool             `json:"apply_to_http"`     // Apply to HTTP port
	ApplyToHTTPS    bool             `json:"apply_to_https"`    // Apply to HTTPS port
	Description     string           `json:"description"`       // Human-readable description
	HitCount        int64            `json:"hit_count"`         // Number of times rule was matched
	LastHit         *time.Time       `json:"last_hit"`          // Last time rule was matched
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	// Compiled fields (not stored in DB)
	compiledCIDR    *net.IPNet       `json:"-"`
	compiledUA      *regexp.Regexp   `json:"-"`
}

// SecurityDB manages security rules
type SecurityDB struct {
	db       *sql.DB
	dbPath   string
	rules    []SecurityRule // Cached rules sorted by priority
	mu       sync.RWMutex
	cacheMu  sync.RWMutex
}

// NewSecurityDB creates a new SecurityDB instance
func NewSecurityDB(configPath string) (*SecurityDB, error) {
	dir := filepath.Dir(configPath)
	dbPath := filepath.Join(dir, "security.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open security database: %w", err)
	}

	// Create table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS security_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'deny',
		priority INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		ip_address TEXT,
		user_agent_match TEXT,
		bandwidth_limit INTEGER DEFAULT 0,
		apply_to_http INTEGER NOT NULL DEFAULT 1,
		apply_to_https INTEGER NOT NULL DEFAULT 1,
		description TEXT,
		hit_count INTEGER DEFAULT 0,
		last_hit DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_security_rules_priority ON security_rules(priority DESC);
	CREATE INDEX IF NOT EXISTS idx_security_rules_enabled ON security_rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_security_rules_type ON security_rules(type);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create security_rules table: %w", err)
	}

	securityDB := &SecurityDB{
		db:     db,
		dbPath: dbPath,
		rules:  []SecurityRule{},
	}

	// Load rules into cache
	if err := securityDB.ReloadRules(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load security rules: %w", err)
	}

	return securityDB, nil
}

// Close closes the database connection
func (s *SecurityDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ReloadRules reloads all rules from database into memory cache
func (s *SecurityDB) ReloadRules() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		SELECT id, name, type, priority, enabled, ip_address, user_agent_match,
		       bandwidth_limit, apply_to_http, apply_to_https, description,
		       hit_count, last_hit, created_at, updated_at
		FROM security_rules
		WHERE enabled = 1
		ORDER BY priority DESC, id ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query security rules: %w", err)
	}
	defer rows.Close()

	var rules []SecurityRule
	for rows.Next() {
		var rule SecurityRule
		var lastHit sql.NullTime
		var ipAddr, uaMatch, desc sql.NullString

		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Type, &rule.Priority, &rule.Enabled,
			&ipAddr, &uaMatch, &rule.BandwidthLimit,
			&rule.ApplyToHTTP, &rule.ApplyToHTTPS, &desc,
			&rule.HitCount, &lastHit, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return fmt.Errorf("failed to scan security rule: %w", err)
		}

		if ipAddr.Valid {
			rule.IPAddress = ipAddr.String
		}
		if uaMatch.Valid {
			rule.UserAgentMatch = uaMatch.String
		}
		if desc.Valid {
			rule.Description = desc.String
		}
		if lastHit.Valid {
			rule.LastHit = &lastHit.Time
		}

		// Compile IP/CIDR
		if rule.IPAddress != "" {
			rule.compiledCIDR = s.parseCIDR(rule.IPAddress)
		}

		// Compile User-Agent regex
		if rule.UserAgentMatch != "" {
			if compiled, err := regexp.Compile(rule.UserAgentMatch); err == nil {
				rule.compiledUA = compiled
			}
		}

		rules = append(rules, rule)
	}

	s.rules = rules
	return nil
}

// parseCIDR parses an IP address or CIDR notation
func (s *SecurityDB) parseCIDR(ipStr string) *net.IPNet {
	// Try CIDR first
	if strings.Contains(ipStr, "/") {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err == nil {
			return ipNet
		}
	}

	// Try single IP
	ip := net.ParseIP(ipStr)
	if ip != nil {
		// Convert to CIDR with /32 or /128
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}

	return nil
}

// MatchResult represents the result of rule matching
type MatchResult struct {
	Allowed        bool
	Denied         bool
	BandwidthLimit int64  // 0 = unlimited
	MatchedRule    *SecurityRule
	Reason         string
}

// CheckAccess checks if an IP/User-Agent combination is allowed
func (s *SecurityDB) CheckAccess(clientIP, userAgent string, isHTTPS bool) MatchResult {
	s.cacheMu.RLock()
	rules := s.rules
	s.cacheMu.RUnlock()

	// If no rules, allow all
	if len(rules) == 0 {
		return MatchResult{Allowed: true, Reason: "no rules configured"}
	}

	clientIPParsed := net.ParseIP(clientIP)
	result := MatchResult{Allowed: true, Reason: "default allow"}

	for i := range rules {
		rule := &rules[i]

		// Check if rule applies to this protocol
		if isHTTPS && !rule.ApplyToHTTPS {
			continue
		}
		if !isHTTPS && !rule.ApplyToHTTP {
			continue
		}

		// Check IP match
		ipMatches := true
		if rule.IPAddress != "" && rule.compiledCIDR != nil {
			if clientIPParsed == nil || !rule.compiledCIDR.Contains(clientIPParsed) {
				ipMatches = false
			}
		} else if rule.IPAddress != "" {
			// Fallback to string comparison
			ipMatches = (clientIP == rule.IPAddress)
		}

		// Check User-Agent match
		uaMatches := true
		if rule.UserAgentMatch != "" {
			if rule.compiledUA != nil {
				uaMatches = rule.compiledUA.MatchString(userAgent)
			} else {
				// Fallback to substring match
				uaMatches = strings.Contains(strings.ToLower(userAgent), strings.ToLower(rule.UserAgentMatch))
			}
		}

		// Both must match (or be empty/any)
		if ipMatches && uaMatches {
			// Update hit count asynchronously
			go s.incrementHitCount(rule.ID)

			switch rule.Type {
			case RuleTypeDeny:
				return MatchResult{
					Allowed:     false,
					Denied:      true,
					MatchedRule: rule,
					Reason:      fmt.Sprintf("denied by rule: %s", rule.Name),
				}
			case RuleTypeAllow:
				return MatchResult{
					Allowed:     true,
					MatchedRule: rule,
					Reason:      fmt.Sprintf("allowed by rule: %s", rule.Name),
				}
			case RuleTypeLimit:
				// Bandwidth limit rule - allow but with limit
				if rule.BandwidthLimit > 0 {
					if result.BandwidthLimit == 0 || rule.BandwidthLimit < result.BandwidthLimit {
						result.BandwidthLimit = rule.BandwidthLimit
						result.MatchedRule = rule
						result.Reason = fmt.Sprintf("bandwidth limited by rule: %s", rule.Name)
					}
				}
			}
		}
	}

	return result
}

// incrementHitCount updates the hit count for a rule
func (s *SecurityDB) incrementHitCount(ruleID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = s.db.Exec(
		"UPDATE security_rules SET hit_count = hit_count + 1, last_hit = ? WHERE id = ?",
		time.Now(), ruleID,
	)
}

// GetAllRules returns all rules (including disabled)
func (s *SecurityDB) GetAllRules() ([]SecurityRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, name, type, priority, enabled, ip_address, user_agent_match,
		       bandwidth_limit, apply_to_http, apply_to_https, description,
		       hit_count, last_hit, created_at, updated_at
		FROM security_rules
		ORDER BY priority DESC, id ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query security rules: %w", err)
	}
	defer rows.Close()

	var rules []SecurityRule
	for rows.Next() {
		var rule SecurityRule
		var lastHit sql.NullTime
		var ipAddr, uaMatch, desc sql.NullString

		if err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Type, &rule.Priority, &rule.Enabled,
			&ipAddr, &uaMatch, &rule.BandwidthLimit,
			&rule.ApplyToHTTP, &rule.ApplyToHTTPS, &desc,
			&rule.HitCount, &lastHit, &rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan security rule: %w", err)
		}

		if ipAddr.Valid {
			rule.IPAddress = ipAddr.String
		}
		if uaMatch.Valid {
			rule.UserAgentMatch = uaMatch.String
		}
		if desc.Valid {
			rule.Description = desc.String
		}
		if lastHit.Valid {
			rule.LastHit = &lastHit.Time
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// GetRule returns a specific rule by ID
func (s *SecurityDB) GetRule(id int64) (*SecurityRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, name, type, priority, enabled, ip_address, user_agent_match,
		       bandwidth_limit, apply_to_http, apply_to_https, description,
		       hit_count, last_hit, created_at, updated_at
		FROM security_rules
		WHERE id = ?
	`

	var rule SecurityRule
	var lastHit sql.NullTime
	var ipAddr, uaMatch, desc sql.NullString

	err := s.db.QueryRow(query, id).Scan(
		&rule.ID, &rule.Name, &rule.Type, &rule.Priority, &rule.Enabled,
		&ipAddr, &uaMatch, &rule.BandwidthLimit,
		&rule.ApplyToHTTP, &rule.ApplyToHTTPS, &desc,
		&rule.HitCount, &lastHit, &rule.CreatedAt, &rule.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get security rule: %w", err)
	}

	if ipAddr.Valid {
		rule.IPAddress = ipAddr.String
	}
	if uaMatch.Valid {
		rule.UserAgentMatch = uaMatch.String
	}
	if desc.Valid {
		rule.Description = desc.String
	}
	if lastHit.Valid {
		rule.LastHit = &lastHit.Time
	}

	return &rule, nil
}

// CreateRule creates a new security rule
func (s *SecurityDB) CreateRule(rule *SecurityRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate rule
	if err := s.validateRule(rule); err != nil {
		return err
	}

	query := `
		INSERT INTO security_rules (
			name, type, priority, enabled, ip_address, user_agent_match,
			bandwidth_limit, apply_to_http, apply_to_https, description,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	result, err := s.db.Exec(query,
		rule.Name, rule.Type, rule.Priority, rule.Enabled,
		nullString(rule.IPAddress), nullString(rule.UserAgentMatch),
		rule.BandwidthLimit, rule.ApplyToHTTP, rule.ApplyToHTTPS,
		nullString(rule.Description), now, now,
	)

	if err != nil {
		return fmt.Errorf("failed to create security rule: %w", err)
	}

	id, _ := result.LastInsertId()
	rule.ID = id
	rule.CreatedAt = now
	rule.UpdatedAt = now

	// Reload cache
	go s.ReloadRules()

	return nil
}

// UpdateRule updates an existing security rule
func (s *SecurityDB) UpdateRule(rule *SecurityRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate rule
	if err := s.validateRule(rule); err != nil {
		return err
	}

	query := `
		UPDATE security_rules SET
			name = ?, type = ?, priority = ?, enabled = ?,
			ip_address = ?, user_agent_match = ?, bandwidth_limit = ?,
			apply_to_http = ?, apply_to_https = ?, description = ?,
			updated_at = ?
		WHERE id = ?
	`

	now := time.Now()
	result, err := s.db.Exec(query,
		rule.Name, rule.Type, rule.Priority, rule.Enabled,
		nullString(rule.IPAddress), nullString(rule.UserAgentMatch),
		rule.BandwidthLimit, rule.ApplyToHTTP, rule.ApplyToHTTPS,
		nullString(rule.Description), now, rule.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update security rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}

	rule.UpdatedAt = now

	// Reload cache
	go s.ReloadRules()

	return nil
}

// DeleteRule deletes a security rule
func (s *SecurityDB) DeleteRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM security_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete security rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}

	// Reload cache
	go s.ReloadRules()

	return nil
}

// validateRule validates a security rule
func (s *SecurityDB) validateRule(rule *SecurityRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	if rule.Type != RuleTypeAllow && rule.Type != RuleTypeDeny && rule.Type != RuleTypeLimit {
		return fmt.Errorf("invalid rule type: %s", rule.Type)
	}

	// Validate IP/CIDR if provided
	if rule.IPAddress != "" {
		if strings.Contains(rule.IPAddress, "/") {
			_, _, err := net.ParseCIDR(rule.IPAddress)
			if err != nil {
				return fmt.Errorf("invalid CIDR notation: %s", rule.IPAddress)
			}
		} else {
			ip := net.ParseIP(rule.IPAddress)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", rule.IPAddress)
			}
		}
	}

	// Validate User-Agent regex if provided
	if rule.UserAgentMatch != "" {
		_, err := regexp.Compile(rule.UserAgentMatch)
		if err != nil {
			return fmt.Errorf("invalid user-agent regex: %v", err)
		}
	}

	// At least one match criteria should be set
	if rule.IPAddress == "" && rule.UserAgentMatch == "" {
		return fmt.Errorf("at least IP address or User-Agent pattern must be specified")
	}

	// Bandwidth limit only valid for limit type
	if rule.Type != RuleTypeLimit && rule.BandwidthLimit > 0 {
		return fmt.Errorf("bandwidth limit can only be set for 'limit' type rules")
	}

	return nil
}

// ResetHitCounts resets all hit counters
func (s *SecurityDB) ResetHitCounts() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE security_rules SET hit_count = 0, last_hit = NULL")
	return err
}

// GetStats returns security statistics
func (s *SecurityDB) GetStats() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make(map[string]interface{})

	// Count rules by type
	var totalRules, allowRules, denyRules, limitRules, enabledRules int64
	s.db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&totalRules)
	s.db.QueryRow("SELECT COUNT(*) FROM security_rules WHERE type = 'allow'").Scan(&allowRules)
	s.db.QueryRow("SELECT COUNT(*) FROM security_rules WHERE type = 'deny'").Scan(&denyRules)
	s.db.QueryRow("SELECT COUNT(*) FROM security_rules WHERE type = 'limit'").Scan(&limitRules)
	s.db.QueryRow("SELECT COUNT(*) FROM security_rules WHERE enabled = 1").Scan(&enabledRules)

	// Total hits
	var totalHits int64
	s.db.QueryRow("SELECT COALESCE(SUM(hit_count), 0) FROM security_rules").Scan(&totalHits)

	stats["total_rules"] = totalRules
	stats["allow_rules"] = allowRules
	stats["deny_rules"] = denyRules
	stats["limit_rules"] = limitRules
	stats["enabled_rules"] = enabledRules
	stats["total_hits"] = totalHits

	return stats, nil
}

// nullString returns sql.NullString for a string
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// GetCachedRuleCount returns the number of cached (active) rules
func (s *SecurityDB) GetCachedRuleCount() int {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return len(s.rules)
}
