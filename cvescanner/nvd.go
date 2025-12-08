package cvescanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// NVDAPIURL is the NVD 2.0 API endpoint for CVE queries
	NVDAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// NVDRateLimitDelay is the delay between API calls without an API key
	NVDRateLimitDelay = 6 * time.Second
	// NVDRateLimitDelayWithKey is the delay between API calls with an API key
	NVDRateLimitDelayWithKey = 600 * time.Millisecond
)

// NVDClient handles communication with the NVD API
type NVDClient struct {
	httpClient *http.Client
	apiKey     string
	lastCall   time.Time
}

// NVDResponse represents the NVD API response structure
type NVDResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Format          string             `json:"format"`
	Version         string             `json:"version"`
	Timestamp       string             `json:"timestamp"`
	Vulnerabilities []NVDVulnerability `json:"vulnerabilities"`
}

// NVDVulnerability represents a single vulnerability from NVD
type NVDVulnerability struct {
	CVE NVDCVE `json:"cve"`
}

// NVDCVE represents the CVE data structure from NVD
type NVDCVE struct {
	ID               string           `json:"id"`
	SourceIdentifier string           `json:"sourceIdentifier"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	VulnStatus       string           `json:"vulnStatus"`
	Descriptions     []NVDDescription `json:"descriptions"`
	Metrics          NVDMetrics       `json:"metrics"`
	Weaknesses       []NVDWeakness    `json:"weaknesses,omitempty"`
	References       []NVDReference   `json:"references,omitempty"`
}

// NVDDescription contains the vulnerability description
type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDMetrics contains CVSS scoring information
type NVDMetrics struct {
	CVSSMetricV31 []NVDCVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV30 []NVDCVSSMetricV30 `json:"cvssMetricV30,omitempty"`
	CVSSMetricV2  []NVDCVSSMetricV2  `json:"cvssMetricV2,omitempty"`
}

// NVDCVSSMetricV31 contains CVSS v3.1 metrics
type NVDCVSSMetricV31 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSV31Data `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

// CVSSV31Data contains the CVSS v3.1 score data
type CVSSV31Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

// NVDCVSSMetricV30 contains CVSS v3.0 metrics
type NVDCVSSMetricV30 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSV30Data `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

// CVSSV30Data contains the CVSS v3.0 score data
type CVSSV30Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

// NVDCVSSMetricV2 contains CVSS v2 metrics
type NVDCVSSMetricV2 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSV2Data `json:"cvssData"`
	BaseSeverity        string     `json:"baseSeverity"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
}

// CVSSV2Data contains the CVSS v2 score data
type CVSSV2Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

// NVDWeakness contains CWE weakness information
type NVDWeakness struct {
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Description []NVDWeaknessDesc `json:"description"`
}

// NVDWeaknessDesc contains the CWE description
type NVDWeaknessDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDReference contains reference URLs
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// CVSSInfo contains extracted CVSS information for storage
type CVSSInfo struct {
	Version      string  `json:"version"` // "3.1", "3.0", or "2.0"
	BaseScore    float64 `json:"base_score"`
	Severity     string  `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	VectorString string  `json:"vector_string"`
	Source       string  `json:"source"` // e.g., "nvd@nist.gov"
}

// NewNVDClient creates a new NVD API client
func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
	}
}

// rateLimitWait waits for rate limiting
func (c *NVDClient) rateLimitWait() {
	delay := NVDRateLimitDelay
	if c.apiKey != "" {
		delay = NVDRateLimitDelayWithKey
	}

	elapsed := time.Since(c.lastCall)
	if elapsed < delay {
		time.Sleep(delay - elapsed)
	}
	c.lastCall = time.Now()
}

// GetCVE fetches a single CVE from NVD
func (c *NVDClient) GetCVE(cveID string) (*NVDCVE, error) {
	c.rateLimitWait()

	reqURL := fmt.Sprintf("%s?cveId=%s", NVDAPIURL, url.QueryEscape(cveID))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found in NVD", cveID)
	}

	return &nvdResp.Vulnerabilities[0].CVE, nil
}

// GetCVEsBatch fetches multiple CVEs from NVD (up to 2000 per request)
func (c *NVDClient) GetCVEsBatch(startIndex, resultsPerPage int) (*NVDResponse, error) {
	c.rateLimitWait()

	reqURL := fmt.Sprintf("%s?startIndex=%d&resultsPerPage=%d", NVDAPIURL, startIndex, resultsPerPage)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, err
	}

	return &nvdResp, nil
}

// ExtractCVSSInfo extracts the best available CVSS information from NVD CVE data
func ExtractCVSSInfo(cve *NVDCVE) *CVSSInfo {
	// Prefer CVSS v3.1, then v3.0, then v2

	// Try CVSS v3.1 first
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		// Prefer NVD's primary assessment
		for _, metric := range cve.Metrics.CVSSMetricV31 {
			if metric.Type == "Primary" {
				return &CVSSInfo{
					Version:      "3.1",
					BaseScore:    metric.CVSSData.BaseScore,
					Severity:     metric.CVSSData.BaseSeverity,
					VectorString: metric.CVSSData.VectorString,
					Source:       metric.Source,
				}
			}
		}
		// Fall back to first available
		metric := cve.Metrics.CVSSMetricV31[0]
		return &CVSSInfo{
			Version:      "3.1",
			BaseScore:    metric.CVSSData.BaseScore,
			Severity:     metric.CVSSData.BaseSeverity,
			VectorString: metric.CVSSData.VectorString,
			Source:       metric.Source,
		}
	}

	// Try CVSS v3.0
	if len(cve.Metrics.CVSSMetricV30) > 0 {
		for _, metric := range cve.Metrics.CVSSMetricV30 {
			if metric.Type == "Primary" {
				return &CVSSInfo{
					Version:      "3.0",
					BaseScore:    metric.CVSSData.BaseScore,
					Severity:     metric.CVSSData.BaseSeverity,
					VectorString: metric.CVSSData.VectorString,
					Source:       metric.Source,
				}
			}
		}
		metric := cve.Metrics.CVSSMetricV30[0]
		return &CVSSInfo{
			Version:      "3.0",
			BaseScore:    metric.CVSSData.BaseScore,
			Severity:     metric.CVSSData.BaseSeverity,
			VectorString: metric.CVSSData.VectorString,
			Source:       metric.Source,
		}
	}

	// Try CVSS v2
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		metric := cve.Metrics.CVSSMetricV2[0]
		return &CVSSInfo{
			Version:      "2.0",
			BaseScore:    metric.CVSSData.BaseScore,
			Severity:     metric.BaseSeverity,
			VectorString: metric.CVSSData.VectorString,
			Source:       metric.Source,
		}
	}

	return nil
}

// GetDescription extracts the English description from NVD CVE
func GetDescription(cve *NVDCVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

// SeverityToUrgency converts NVD severity to Debian urgency format
func SeverityToUrgency(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "not yet assigned"
	}
}

// UrgencyToSeverity converts Debian urgency to NVD severity format
func UrgencyToSeverity(urgency string) string {
	switch strings.ToLower(urgency) {
	case "critical", "high**":
		return "CRITICAL"
	case "high", "high*":
		return "HIGH"
	case "medium", "medium**", "medium*":
		return "MEDIUM"
	case "low", "low**", "low*":
		return "LOW"
	case "unimportant":
		return "LOW"
	default:
		return ""
	}
}
