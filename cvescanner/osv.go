package cvescanner

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// OSVDebianAllURL is the URL to download all Debian vulnerabilities from OSV
	OSVDebianAllURL = "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"
	// OSVAPIURL is the OSV query API endpoint
	OSVAPIURL = "https://api.osv.dev/v1/query"
	// OSVVulnURL is the URL to get a specific vulnerability
	OSVVulnURL = "https://api.osv.dev/v1/vulns"
)

// OSVClient handles communication with OSV.dev
type OSVClient struct {
	httpClient *http.Client
}

// OSVVulnerability represents a vulnerability in OSV format
type OSVVulnerability struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Modified         string          `json:"modified"`
	Published        string          `json:"published"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
	References       []OSVReference  `json:"references,omitempty"`
	Affected         []OSVAffected   `json:"affected,omitempty"`
	Severity         []OSVSeverity   `json:"severity,omitempty"`
	Credits          []OSVCredit     `json:"credits,omitempty"`
	SchemaVersion    string          `json:"schema_version,omitempty"`
}

// OSVReference contains reference URLs
type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// OSVAffected contains affected package information
type OSVAffected struct {
	Package           OSVPackage      `json:"package"`
	Ranges            []OSVRange      `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

// OSVPackage identifies the affected package
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl,omitempty"`
}

// OSVRange defines version ranges for affected packages
type OSVRange struct {
	Type   string     `json:"type"` // SEMVER, ECOSYSTEM, GIT
	Repo   string     `json:"repo,omitempty"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent defines a range event
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// OSVSeverity contains CVSS severity information
type OSVSeverity struct {
	Type  string `json:"type"`  // CVSS_V2, CVSS_V3
	Score string `json:"score"` // CVSS vector string
}

// OSVCredit contains credit information
type OSVCredit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// OSVQueryRequest is the request body for OSV queries
type OSVQueryRequest struct {
	Commit  string      `json:"commit,omitempty"`
	Version string      `json:"version,omitempty"`
	Package *OSVPackage `json:"package,omitempty"`
}

// OSVQueryResponse is the response from OSV query API
type OSVQueryResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVDatabase holds the downloaded OSV Debian database
type OSVDatabase struct {
	Vulnerabilities map[string]*OSVVulnerability // CVE ID -> vulnerability
	LastUpdated     time.Time
}

// NewOSVClient creates a new OSV client
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// DownloadDebianDatabase downloads the complete Debian OSV database
func (c *OSVClient) DownloadDebianDatabase(cachePath string) (*OSVDatabase, error) {
	resp, err := c.httpClient.Get(OSVDebianAllURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download OSV Debian database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}

	// Read the zip file into memory
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV data: %w", err)
	}

	// Parse the zip file
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	db := &OSVDatabase{
		Vulnerabilities: make(map[string]*OSVVulnerability),
		LastUpdated:     time.Now(),
	}

	for _, file := range zipReader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		var vuln OSVVulnerability
		if err := json.Unmarshal(data, &vuln); err != nil {
			continue
		}

		// Store by ID and also by any CVE aliases
		db.Vulnerabilities[vuln.ID] = &vuln

		// Index by CVE aliases
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				db.Vulnerabilities[alias] = &vuln
			}
		}
	}

	// Save to cache
	if cachePath != "" {
		if err := c.saveCache(cachePath, db); err != nil {
			// Log but don't fail
			fmt.Printf("Warning: failed to save OSV cache: %v\n", err)
		}
	}

	return db, nil
}

// saveCache saves the OSV database to a cache file
func (c *OSVClient) saveCache(cachePath string, db *OSVDatabase) error {
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}

	data, err := json.Marshal(db)
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0644)
}

// LoadCache loads the OSV database from cache
func (c *OSVClient) LoadCache(cachePath string, maxAge time.Duration) (*OSVDatabase, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var db OSVDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}

	if time.Since(db.LastUpdated) > maxAge {
		return nil, fmt.Errorf("cache expired")
	}

	return &db, nil
}

// QueryPackage queries OSV for vulnerabilities affecting a specific package
func (c *OSVClient) QueryPackage(packageName, version, ecosystem string) (*OSVQueryResponse, error) {
	reqBody := OSVQueryRequest{
		Version: version,
		Package: &OSVPackage{
			Name:      packageName,
			Ecosystem: ecosystem,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(OSVAPIURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result OSVQueryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetVulnerability fetches a specific vulnerability by ID
func (c *OSVClient) GetVulnerability(vulnID string) (*OSVVulnerability, error) {
	url := fmt.Sprintf("%s/%s", OSVVulnURL, vulnID)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vuln OSVVulnerability
	if err := json.Unmarshal(body, &vuln); err != nil {
		return nil, err
	}

	return &vuln, nil
}

// ExtractCVSSFromOSV extracts CVSS information from OSV vulnerability
func ExtractCVSSFromOSV(vuln *OSVVulnerability) *CVSSInfo {
	if len(vuln.Severity) == 0 {
		return nil
	}

	// Prefer CVSS v3 over v2
	var cvssV3, cvssV2 *OSVSeverity
	for i := range vuln.Severity {
		sev := &vuln.Severity[i]
		if sev.Type == "CVSS_V3" {
			cvssV3 = sev
		} else if sev.Type == "CVSS_V2" {
			cvssV2 = sev
		}
	}

	if cvssV3 != nil {
		score, severity := parseCVSSVector(cvssV3.Score)
		return &CVSSInfo{
			Version:      "3.1",
			BaseScore:    score,
			Severity:     severity,
			VectorString: cvssV3.Score,
			Source:       "osv.dev",
		}
	}

	if cvssV2 != nil {
		score, severity := parseCVSSVector(cvssV2.Score)
		return &CVSSInfo{
			Version:      "2.0",
			BaseScore:    score,
			Severity:     severity,
			VectorString: cvssV2.Score,
			Source:       "osv.dev",
		}
	}

	return nil
}

// parseCVSSVector extracts score from CVSS vector string
func parseCVSSVector(vector string) (float64, string) {
	// CVSS v3 vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	// We need to calculate or estimate the score from the vector

	// For simplicity, we'll estimate severity from vector components
	// In a real implementation, you'd calculate the actual CVSS score

	vector = strings.ToUpper(vector)

	// Check for high impact indicators
	hasHighImpact := strings.Contains(vector, "/C:H") || strings.Contains(vector, "/I:H") || strings.Contains(vector, "/A:H")
	hasNetworkVector := strings.Contains(vector, "/AV:N")
	hasLowComplexity := strings.Contains(vector, "/AC:L")
	hasNoPrivileges := strings.Contains(vector, "/PR:N")

	// Estimate score based on vector components
	var score float64
	var severity string

	if hasNetworkVector && hasLowComplexity && hasNoPrivileges && hasHighImpact {
		score = 9.8
		severity = "CRITICAL"
	} else if hasNetworkVector && hasHighImpact {
		score = 8.1
		severity = "HIGH"
	} else if hasHighImpact {
		score = 7.0
		severity = "HIGH"
	} else if hasNetworkVector {
		score = 5.3
		severity = "MEDIUM"
	} else {
		score = 3.9
		severity = "LOW"
	}

	return score, severity
}

// GetCVEIDFromOSV extracts CVE ID from OSV vulnerability
func GetCVEIDFromOSV(vuln *OSVVulnerability) string {
	// Check if the ID itself is a CVE
	if strings.HasPrefix(vuln.ID, "CVE-") {
		return vuln.ID
	}

	// Check aliases
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}

	return ""
}

// GetFixedVersion extracts the fixed version from OSV affected data
func GetFixedVersionFromOSV(vuln *OSVVulnerability, packageName string) string {
	for _, affected := range vuln.Affected {
		if affected.Package.Name == packageName {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						return event.Fixed
					}
				}
			}
		}
	}
	return ""
}

// IsPackageAffected checks if a specific package version is affected
func IsPackageAffectedOSV(vuln *OSVVulnerability, packageName, version string) bool {
	for _, affected := range vuln.Affected {
		if affected.Package.Name != packageName {
			continue
		}

		// Check specific versions list
		for _, v := range affected.Versions {
			if v == version {
				return true
			}
		}

		// Check version ranges
		for _, r := range affected.Ranges {
			if isVersionInRange(version, r) {
				return true
			}
		}
	}
	return false
}

// isVersionInRange checks if a version falls within an OSV range
func isVersionInRange(version string, r OSVRange) bool {
	var introduced, fixed string

	for _, event := range r.Events {
		if event.Introduced != "" {
			introduced = event.Introduced
		}
		if event.Fixed != "" {
			fixed = event.Fixed
		}
	}

	// If introduced is "0", it means all versions before fixed are affected
	if introduced == "0" || introduced == "" {
		if fixed == "" {
			return true // All versions affected
		}
		// Version is affected if it's less than fixed
		return compareDebianVersions(version, fixed) < 0
	}

	// Check if version >= introduced
	if compareDebianVersions(version, introduced) < 0 {
		return false
	}

	// Check if version < fixed (if fixed exists)
	if fixed != "" {
		return compareDebianVersions(version, fixed) < 0
	}

	return true // No fixed version, so still affected
}
