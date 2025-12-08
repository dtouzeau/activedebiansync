package cvescanner

import (
	"activedebiansync/config"
	"activedebiansync/utils"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ulikunitz/xz"
)

const (
	// DebianSecurityTrackerURL is the URL to fetch CVE data from Debian Security Tracker
	DebianSecurityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
)

// CVEScanner handles CVE scanning for the local Debian repository
type CVEScanner struct {
	config         *config.Config
	logger         *utils.Logger
	httpClient     *http.Client
	cveData        *CVEDatabase
	cachePath      string
	cacheTime      time.Time
	lastScanResult *ScanResult
	nvdClient      *NVDClient
	osvClient      *OSVClient
	osvData        *OSVDatabase
	cvssCache      map[string]*CVSSInfo // CVE ID -> CVSS info
	mu             sync.RWMutex
}

// CVEDatabase represents the Debian Security Tracker JSON structure
type CVEDatabase map[string]PackageCVEs // package name -> CVE data

// PackageCVEs contains CVE information for a package
type PackageCVEs map[string]CVEInfo // CVE ID -> CVE info

// CVEInfo contains information about a specific CVE
type CVEInfo struct {
	Description string                   `json:"description"`
	Scope       string                   `json:"scope"`
	Releases    map[string]ReleaseStatus `json:"releases"` // release name -> status
	Debianbug   int64                    `json:"debianbug,omitempty"`
}

// ReleaseStatus contains the status of a CVE for a specific release
type ReleaseStatus struct {
	Status       string            `json:"status"`
	Urgency      string            `json:"urgency"`
	FixedVersion string            `json:"fixed_version,omitempty"`
	Repositories map[string]string `json:"repositories,omitempty"` // repo name -> version
}

// VulnerablePackage represents a package with known vulnerabilities
type VulnerablePackage struct {
	Package      string      `json:"package"`
	Version      string      `json:"version"`
	Release      string      `json:"release"`
	Component    string      `json:"component"`
	Architecture string      `json:"architecture"`
	CVEs         []CVEDetail `json:"cves"`
	TotalCVEs    int         `json:"total_cves"`
	Critical     int         `json:"critical"`
	High         int         `json:"high"`
	Medium       int         `json:"medium"`
	Low          int         `json:"low"`
	Unassigned   int         `json:"unassigned"`
}

// CVEDetail contains detailed information about a CVE affecting a package
type CVEDetail struct {
	CVEID        string   `json:"cve_id"`
	Description  string   `json:"description"`
	Status       string   `json:"status"`
	Urgency      string   `json:"urgency"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	DebianBug    int64    `json:"debian_bug,omitempty"`
	CVSSScore    float64  `json:"cvss_score,omitempty"`
	CVSSSeverity string   `json:"cvss_severity,omitempty"`
	CVSSVector   string   `json:"cvss_vector,omitempty"`
	CVSSVersion  string   `json:"cvss_version,omitempty"`
	CVSSSource   string   `json:"cvss_source,omitempty"`
	DataSources  []string `json:"data_sources,omitempty"`
}

// ScanResult contains the results of a CVE scan
type ScanResult struct {
	ScanTime           time.Time           `json:"scan_time"`
	Release            string              `json:"release,omitempty"`
	Component          string              `json:"component,omitempty"`
	Architecture       string              `json:"architecture,omitempty"`
	TotalPackages      int                 `json:"total_packages"`
	VulnerablePackages int                 `json:"vulnerable_packages"`
	TotalCVEs          int                 `json:"total_cves"`
	CriticalCVEs       int                 `json:"critical_cves"`
	HighCVEs           int                 `json:"high_cves"`
	MediumCVEs         int                 `json:"medium_cves"`
	LowCVEs            int                 `json:"low_cves"`
	UnassignedCVEs     int                 `json:"unassigned_cves"`
	CVEDataLastUpdated time.Time           `json:"cve_data_last_updated"`
	Packages           []VulnerablePackage `json:"packages,omitempty"`
}

// ScanSummary provides a quick overview of vulnerabilities
type ScanSummary struct {
	ScanTime           time.Time                  `json:"scan_time"`
	TotalPackages      int                        `json:"total_packages"`
	VulnerablePackages int                        `json:"vulnerable_packages"`
	TotalCVEs          int                        `json:"total_cves"`
	ByUrgency          map[string]int             `json:"by_urgency"`
	ByRelease          map[string]ReleaseSummary  `json:"by_release"`
	TopVulnerable      []VulnerablePackageSummary `json:"top_vulnerable"`
	CVEDataLastUpdated time.Time                  `json:"cve_data_last_updated"`
}

// ReleaseSummary contains vulnerability summary for a release
type ReleaseSummary struct {
	TotalPackages      int `json:"total_packages"`
	VulnerablePackages int `json:"vulnerable_packages"`
	TotalCVEs          int `json:"total_cves"`
}

// VulnerablePackageSummary is a brief summary of a vulnerable package
type VulnerablePackageSummary struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	Release    string `json:"release"`
	CVECount   int    `json:"cve_count"`
	MaxUrgency string `json:"max_urgency"`
}

// RepositoryPackage represents a package in the local repository
type RepositoryPackage struct {
	Name         string
	Version      string
	Release      string
	Component    string
	Architecture string
	Description  string
	Filename     string
}

// NewCVEScanner creates a new CVE scanner instance
func NewCVEScanner(cfg *config.Config, logger *utils.Logger) *CVEScanner {
	cfgData := cfg.Get()
	cachePath := filepath.Join(filepath.Dir(cfgData.LogPath), "cve_cache.json")

	scanner := &CVEScanner{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		cachePath:  cachePath,
		cvssCache:  make(map[string]*CVSSInfo),
	}

	// Initialize NVD client if enabled
	if cfgData.CVENVDEnabled {
		scanner.nvdClient = NewNVDClient(cfgData.CVENVDAPIKey)
	}

	// Initialize OSV client if enabled
	if cfgData.CVEOSVEnabled {
		scanner.osvClient = NewOSVClient()
	}

	return scanner
}

// UpdateCVEData fetches the latest CVE data from all enabled sources
func (s *CVEScanner) UpdateCVEData() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Fetch Debian Security Tracker data
	s.logger.LogInfo("Fetching CVE data from Debian Security Tracker...")

	resp, err := s.httpClient.Get(DebianSecurityTrackerURL)
	if err != nil {
		return fmt.Errorf("failed to fetch CVE data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch CVE data: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read CVE data: %w", err)
	}

	var cveDB CVEDatabase
	if err := json.Unmarshal(data, &cveDB); err != nil {
		return fmt.Errorf("failed to parse CVE data: %w", err)
	}

	s.cveData = &cveDB
	s.cacheTime = time.Now()

	// Save to cache file
	if err := s.saveCacheToFile(data); err != nil {
		s.logger.LogError("Failed to save CVE cache: %v", err)
	}

	s.logger.LogInfo("Debian Security Tracker: %d packages with CVE information", len(cveDB))

	// 2. Fetch OSV.dev Debian database if enabled
	cfg := s.config.Get()
	if cfg.CVEOSVEnabled && s.osvClient != nil {
		s.logger.LogInfo("Fetching CVE data from OSV.dev...")
		osvCachePath := filepath.Join(filepath.Dir(s.cachePath), "osv_cache.json")
		osvDB, err := s.osvClient.DownloadDebianDatabase(osvCachePath)
		if err != nil {
			s.logger.LogError("Failed to fetch OSV data: %v", err)
		} else {
			s.osvData = osvDB
			s.logger.LogInfo("OSV.dev: %d vulnerabilities loaded", len(osvDB.Vulnerabilities))

			// Extract CVSS data from OSV and cache it
			for cveID, vuln := range osvDB.Vulnerabilities {
				if strings.HasPrefix(cveID, "CVE-") {
					if cvss := ExtractCVSSFromOSV(vuln); cvss != nil {
						if _, exists := s.cvssCache[cveID]; !exists {
							s.cvssCache[cveID] = cvss
						}
					}
				}
			}
			s.logger.LogInfo("CVSS cache: %d entries from OSV", len(s.cvssCache))
		}
	}

	return nil
}

// GetCVSSInfo returns CVSS information for a CVE, fetching from NVD if needed
func (s *CVEScanner) GetCVSSInfo(cveID string) *CVSSInfo {
	s.mu.RLock()
	if cvss, exists := s.cvssCache[cveID]; exists {
		s.mu.RUnlock()
		return cvss
	}
	s.mu.RUnlock()

	// If NVD is enabled, try to fetch CVSS from NVD
	cfg := s.config.Get()
	if cfg.CVENVDEnabled && s.nvdClient != nil {
		nvdCVE, err := s.nvdClient.GetCVE(cveID)
		if err == nil {
			if cvss := ExtractCVSSInfo(nvdCVE); cvss != nil {
				s.mu.Lock()
				s.cvssCache[cveID] = cvss
				s.mu.Unlock()
				return cvss
			}
		}
	}

	return nil
}

// GetCVSSInfoBatch returns CVSS info for multiple CVEs, using cache when available
func (s *CVEScanner) GetCVSSInfoBatch(cveIDs []string) map[string]*CVSSInfo {
	result := make(map[string]*CVSSInfo)

	s.mu.RLock()
	for _, cveID := range cveIDs {
		if cvss, exists := s.cvssCache[cveID]; exists {
			result[cveID] = cvss
		}
	}
	s.mu.RUnlock()

	return result
}

// getCVSSFromCache returns CVSS info from cache without locking (internal use)
func (s *CVEScanner) getCVSSFromCache(cveID string) *CVSSInfo {
	if cvss, exists := s.cvssCache[cveID]; exists {
		return cvss
	}
	return nil
}

// saveCacheToFile saves CVE data to a cache file
func (s *CVEScanner) saveCacheToFile(data []byte) error {
	cacheDir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}

	// Create a wrapper with timestamp
	wrapper := struct {
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}{
		Timestamp: time.Now(),
		Data:      data,
	}

	wrapperData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	return os.WriteFile(s.cachePath, wrapperData, 0644)
}

// getCacheExpiry returns the cache expiry duration from config
func (s *CVEScanner) getCacheExpiry() time.Duration {
	cfg := s.config.Get()
	hours := cfg.CVECacheExpiryHours
	if hours <= 0 {
		hours = 6 // Default 6 hours
	}
	return time.Duration(hours) * time.Hour
}

// loadCacheFromFile loads CVE data from cache file if valid
func (s *CVEScanner) loadCacheFromFile() error {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return err
	}

	var wrapper struct {
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}

	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	// Check if cache is expired
	if time.Since(wrapper.Timestamp) > s.getCacheExpiry() {
		return fmt.Errorf("cache expired")
	}

	var cveDB CVEDatabase
	if err := json.Unmarshal(wrapper.Data, &cveDB); err != nil {
		return err
	}

	s.cveData = &cveDB
	s.cacheTime = wrapper.Timestamp
	return nil
}

// EnsureCVEData ensures CVE data is loaded (from cache or by fetching)
func (s *CVEScanner) EnsureCVEData() error {
	s.mu.RLock()
	if s.cveData != nil && time.Since(s.cacheTime) < s.getCacheExpiry() {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	// Try loading from cache first
	if err := s.loadCacheFromFile(); err == nil {
		s.logger.LogInfo("Loaded CVE data from cache (age: %s)", time.Since(s.cacheTime).Round(time.Minute))
		return nil
	}

	// Fetch fresh data
	return s.UpdateCVEData()
}

// GetCVEDataAge returns how old the CVE data is
func (s *CVEScanner) GetCVEDataAge() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.cacheTime)
}

// GetCVEDataTimestamp returns when CVE data was last updated
func (s *CVEScanner) GetCVEDataTimestamp() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheTime
}

// parsePackagesFile parses a Packages file and returns the list of packages
func (s *CVEScanner) parsePackagesFile(packagesPath string) ([]RepositoryPackage, error) {
	file, err := os.Open(packagesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Packages file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Detect compression type
	if strings.HasSuffix(packagesPath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	} else if strings.HasSuffix(packagesPath, ".xz") {
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = xzReader
	}

	var packages []RepositoryPackage
	var currentPkg RepositoryPackage

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if currentPkg.Name != "" {
				packages = append(packages, currentPkg)
			}
			currentPkg = RepositoryPackage{}
			continue
		}

		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Package":
				currentPkg.Name = value
			case "Version":
				currentPkg.Version = value
			case "Description":
				currentPkg.Description = value
			case "Filename":
				currentPkg.Filename = value
			case "Architecture":
				currentPkg.Architecture = value
			}
		}
	}

	// Don't forget the last package
	if currentPkg.Name != "" {
		packages = append(packages, currentPkg)
	}

	return packages, scanner.Err()
}

// getRepositoryPackages scans all Packages files in the repository
func (s *CVEScanner) getRepositoryPackages(release, component, architecture string) ([]RepositoryPackage, error) {
	cfg := s.config.Get()
	var allPackages []RepositoryPackage

	releases := cfg.DebianReleases
	if release != "" {
		releases = []string{release}
	}

	components := cfg.DebianComponents
	if component != "" {
		components = []string{component}
	}

	architectures := cfg.DebianArchs
	if architecture != "" {
		architectures = []string{architecture}
	}

	for _, rel := range releases {
		for _, comp := range components {
			for _, arch := range architectures {
				// Try .gz first, then .xz
				packagesPath := filepath.Join(cfg.RepositoryPath, "dists", rel, comp,
					fmt.Sprintf("binary-%s", arch), "Packages.gz")

				if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
					packagesPath = filepath.Join(cfg.RepositoryPath, "dists", rel, comp,
						fmt.Sprintf("binary-%s", arch), "Packages.xz")
					if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
						continue
					}
				}

				packages, err := s.parsePackagesFile(packagesPath)
				if err != nil {
					s.logger.LogError("Failed to parse %s: %v", packagesPath, err)
					continue
				}

				// Add release/component info
				for i := range packages {
					packages[i].Release = rel
					packages[i].Component = comp
					if packages[i].Architecture == "" {
						packages[i].Architecture = arch
					}
				}

				allPackages = append(allPackages, packages...)
			}
		}
	}

	return allPackages, nil
}

// checkPackageCVEs checks if a package has known CVEs
func (s *CVEScanner) checkPackageCVEs(pkg RepositoryPackage) *VulnerablePackage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cveData == nil {
		return nil
	}

	packageCVEs, exists := (*s.cveData)[pkg.Name]
	if !exists {
		return nil
	}

	// Map Debian release codenames
	releaseMap := map[string]string{
		"bookworm": "bookworm",
		"trixie":   "trixie",
		"sid":      "sid",
		"bullseye": "bullseye",
		"buster":   "buster",
	}

	debianRelease := releaseMap[pkg.Release]
	if debianRelease == "" {
		debianRelease = pkg.Release
	}

	var cveDetails []CVEDetail
	critical, high, medium, low, unassigned := 0, 0, 0, 0, 0

	for cveID, cveInfo := range packageCVEs {
		releaseStatus, exists := cveInfo.Releases[debianRelease]
		if !exists {
			continue
		}

		// Check if the package is vulnerable
		// Status can be: "open", "resolved", "undetermined"
		if releaseStatus.Status != "open" && releaseStatus.Status != "undetermined" {
			// If resolved, check if our version is older than the fixed version
			if releaseStatus.FixedVersion != "" && releaseStatus.Status == "resolved" {
				if !s.isVersionVulnerable(pkg.Version, releaseStatus.FixedVersion) {
					continue
				}
			} else {
				continue
			}
		}

		detail := CVEDetail{
			CVEID:        cveID,
			Description:  cveInfo.Description,
			Status:       releaseStatus.Status,
			Urgency:      releaseStatus.Urgency,
			FixedVersion: releaseStatus.FixedVersion,
			DebianBug:    cveInfo.Debianbug,
			DataSources:  []string{"debian"},
		}

		// Try to get CVSS info from cache (populated by OSV or NVD)
		if cvss := s.getCVSSFromCache(cveID); cvss != nil {
			detail.CVSSScore = cvss.BaseScore
			detail.CVSSSeverity = cvss.Severity
			detail.CVSSVector = cvss.VectorString
			detail.CVSSVersion = cvss.Version
			detail.CVSSSource = cvss.Source
			detail.DataSources = append(detail.DataSources, cvss.Source)

			// If Debian urgency is unassigned, use CVSS severity
			if releaseStatus.Urgency == "" || releaseStatus.Urgency == "not yet assigned" {
				detail.Urgency = SeverityToUrgency(cvss.Severity)
			}
		}

		cveDetails = append(cveDetails, detail)

		// Count by urgency (use enhanced urgency if available)
		effectiveUrgency := strings.ToLower(detail.Urgency)
		switch effectiveUrgency {
		case "critical":
			critical++
		case "high", "high**":
			high++
		case "medium", "medium**":
			medium++
		case "low", "low**", "unimportant":
			low++
		case "not yet assigned", "":
			unassigned++
		default:
			if strings.Contains(effectiveUrgency, "critical") {
				critical++
			} else {
				unassigned++
			}
		}
	}

	if len(cveDetails) == 0 {
		return nil
	}

	// Sort CVEs by urgency (high first)
	sort.Slice(cveDetails, func(i, j int) bool {
		return urgencyPriority(cveDetails[i].Urgency) > urgencyPriority(cveDetails[j].Urgency)
	})

	return &VulnerablePackage{
		Package:      pkg.Name,
		Version:      pkg.Version,
		Release:      pkg.Release,
		Component:    pkg.Component,
		Architecture: pkg.Architecture,
		CVEs:         cveDetails,
		TotalCVEs:    len(cveDetails),
		Critical:     critical,
		High:         high,
		Medium:       medium,
		Low:          low,
		Unassigned:   unassigned,
	}
}

// urgencyPriority returns a numeric priority for CVE urgency
func urgencyPriority(urgency string) int {
	urgency = strings.ToLower(urgency)
	switch {
	case strings.Contains(urgency, "critical"):
		return 5
	case strings.HasPrefix(urgency, "high"):
		return 4
	case strings.HasPrefix(urgency, "medium"):
		return 3
	case strings.HasPrefix(urgency, "low"):
		return 2
	default:
		return 1
	}
}

// isVersionVulnerable checks if version is vulnerable (older than fixedVersion)
// Uses Debian version comparison
func (s *CVEScanner) isVersionVulnerable(version, fixedVersion string) bool {
	// Simple comparison - in production, use dpkg --compare-versions
	return compareDebianVersions(version, fixedVersion) < 0
}

// compareDebianVersions compares two Debian version strings
// Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
func compareDebianVersions(v1, v2 string) int {
	// Parse epoch:upstream-revision format
	epoch1, upstream1, revision1 := parseDebianVersion(v1)
	epoch2, upstream2, revision2 := parseDebianVersion(v2)

	// Compare epochs
	if epoch1 != epoch2 {
		if epoch1 < epoch2 {
			return -1
		}
		return 1
	}

	// Compare upstream versions
	cmp := compareVersionParts(upstream1, upstream2)
	if cmp != 0 {
		return cmp
	}

	// Compare revisions
	return compareVersionParts(revision1, revision2)
}

// parseDebianVersion parses epoch:upstream-revision format
func parseDebianVersion(v string) (int, string, string) {
	epoch := 0
	upstream := v
	revision := ""

	// Extract epoch
	if idx := strings.Index(v, ":"); idx != -1 {
		fmt.Sscanf(v[:idx], "%d", &epoch)
		upstream = v[idx+1:]
	}

	// Extract revision (last hyphen)
	if idx := strings.LastIndex(upstream, "-"); idx != -1 {
		revision = upstream[idx+1:]
		upstream = upstream[:idx]
	}

	return epoch, upstream, revision
}

// compareVersionParts compares version string parts
func compareVersionParts(v1, v2 string) int {
	// Split into alternating non-digit and digit parts
	re := regexp.MustCompile(`(\d+|\D+)`)
	parts1 := re.FindAllString(v1, -1)
	parts2 := re.FindAllString(v2, -1)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		// Check if both are numeric
		isDigit1 := len(p1) > 0 && p1[0] >= '0' && p1[0] <= '9'
		isDigit2 := len(p2) > 0 && p2[0] >= '0' && p2[0] <= '9'

		if isDigit1 && isDigit2 {
			// Numeric comparison
			var n1, n2 int
			fmt.Sscanf(p1, "%d", &n1)
			fmt.Sscanf(p2, "%d", &n2)
			if n1 != n2 {
				if n1 < n2 {
					return -1
				}
				return 1
			}
		} else {
			// Lexical comparison with special rules
			cmp := strings.Compare(p1, p2)
			if cmp != 0 {
				return cmp
			}
		}
	}

	return 0
}

// Scan performs a CVE scan on the repository
func (s *CVEScanner) Scan(release, component, architecture string, includePackages bool) (*ScanResult, error) {
	// Ensure CVE data is loaded
	if err := s.EnsureCVEData(); err != nil {
		return nil, fmt.Errorf("failed to load CVE data: %w", err)
	}

	s.logger.LogInfo("Starting CVE scan (release=%s, component=%s, arch=%s)",
		release, component, architecture)

	// Get all packages from repository
	packages, err := s.getRepositoryPackages(release, component, architecture)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository packages: %w", err)
	}

	s.logger.LogInfo("Scanning %d packages for CVEs...", len(packages))

	result := &ScanResult{
		ScanTime:           time.Now(),
		Release:            release,
		Component:          component,
		Architecture:       architecture,
		TotalPackages:      len(packages),
		CVEDataLastUpdated: s.cacheTime,
	}

	var vulnerablePackages []VulnerablePackage

	for _, pkg := range packages {
		vulnPkg := s.checkPackageCVEs(pkg)
		if vulnPkg != nil {
			vulnerablePackages = append(vulnerablePackages, *vulnPkg)
			result.TotalCVEs += vulnPkg.TotalCVEs
			result.CriticalCVEs += vulnPkg.Critical
			result.HighCVEs += vulnPkg.High
			result.MediumCVEs += vulnPkg.Medium
			result.LowCVEs += vulnPkg.Low
			result.UnassignedCVEs += vulnPkg.Unassigned
		}
	}

	result.VulnerablePackages = len(vulnerablePackages)

	// Sort by severity (most severe first)
	sort.Slice(vulnerablePackages, func(i, j int) bool {
		// Compare by highest severity count
		if vulnerablePackages[i].Critical != vulnerablePackages[j].Critical {
			return vulnerablePackages[i].Critical > vulnerablePackages[j].Critical
		}
		if vulnerablePackages[i].High != vulnerablePackages[j].High {
			return vulnerablePackages[i].High > vulnerablePackages[j].High
		}
		if vulnerablePackages[i].Medium != vulnerablePackages[j].Medium {
			return vulnerablePackages[i].Medium > vulnerablePackages[j].Medium
		}
		return vulnerablePackages[i].TotalCVEs > vulnerablePackages[j].TotalCVEs
	})

	if includePackages {
		result.Packages = vulnerablePackages
	}

	s.logger.LogInfo("CVE scan complete: %d/%d packages vulnerable, %d total CVEs",
		result.VulnerablePackages, result.TotalPackages, result.TotalCVEs)

	// Store result for later retrieval
	s.mu.Lock()
	s.lastScanResult = result
	s.mu.Unlock()

	return result, nil
}

// GetSummary returns a summary of CVE status across all releases
func (s *CVEScanner) GetSummary() (*ScanSummary, error) {
	if err := s.EnsureCVEData(); err != nil {
		return nil, fmt.Errorf("failed to load CVE data: %w", err)
	}

	cfg := s.config.Get()
	summary := &ScanSummary{
		ScanTime:           time.Now(),
		ByUrgency:          make(map[string]int),
		ByRelease:          make(map[string]ReleaseSummary),
		CVEDataLastUpdated: s.cacheTime,
	}

	for _, release := range cfg.DebianReleases {
		result, err := s.Scan(release, "", "", false)
		if err != nil {
			s.logger.LogError("Failed to scan release %s: %v", release, err)
			continue
		}

		summary.TotalPackages += result.TotalPackages
		summary.VulnerablePackages += result.VulnerablePackages
		summary.TotalCVEs += result.TotalCVEs

		summary.ByUrgency["critical"] += result.CriticalCVEs
		summary.ByUrgency["high"] += result.HighCVEs
		summary.ByUrgency["medium"] += result.MediumCVEs
		summary.ByUrgency["low"] += result.LowCVEs
		summary.ByUrgency["unassigned"] += result.UnassignedCVEs

		summary.ByRelease[release] = ReleaseSummary{
			TotalPackages:      result.TotalPackages,
			VulnerablePackages: result.VulnerablePackages,
			TotalCVEs:          result.TotalCVEs,
		}
	}

	// Get top vulnerable packages
	fullResult, err := s.Scan("", "", "", true)
	if err == nil && len(fullResult.Packages) > 0 {
		limit := 10
		if len(fullResult.Packages) < limit {
			limit = len(fullResult.Packages)
		}
		for i := 0; i < limit; i++ {
			pkg := fullResult.Packages[i]
			maxUrgency := "low"
			if pkg.Critical > 0 {
				maxUrgency = "critical"
			} else if pkg.High > 0 {
				maxUrgency = "high"
			} else if pkg.Medium > 0 {
				maxUrgency = "medium"
			}
			summary.TopVulnerable = append(summary.TopVulnerable, VulnerablePackageSummary{
				Package:    pkg.Package,
				Version:    pkg.Version,
				Release:    pkg.Release,
				CVECount:   pkg.TotalCVEs,
				MaxUrgency: maxUrgency,
			})
		}
	}

	return summary, nil
}

// GetPackageCVEs returns CVE information for a specific package
func (s *CVEScanner) GetPackageCVEs(packageName, release string) (*VulnerablePackage, error) {
	if err := s.EnsureCVEData(); err != nil {
		return nil, fmt.Errorf("failed to load CVE data: %w", err)
	}

	// Get package info from repository
	packages, err := s.getRepositoryPackages(release, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get repository packages: %w", err)
	}

	for _, pkg := range packages {
		if pkg.Name == packageName && (release == "" || pkg.Release == release) {
			vulnPkg := s.checkPackageCVEs(pkg)
			if vulnPkg != nil {
				return vulnPkg, nil
			}
			// Package exists but has no CVEs
			return &VulnerablePackage{
				Package:      pkg.Name,
				Version:      pkg.Version,
				Release:      pkg.Release,
				Component:    pkg.Component,
				Architecture: pkg.Architecture,
				CVEs:         []CVEDetail{},
				TotalCVEs:    0,
			}, nil
		}
	}

	return nil, fmt.Errorf("package not found: %s", packageName)
}

// SearchCVE searches for information about a specific CVE
func (s *CVEScanner) SearchCVE(cveID string) (map[string]interface{}, error) {
	if err := s.EnsureCVEData(); err != nil {
		return nil, fmt.Errorf("failed to load CVE data: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cveData == nil {
		return nil, fmt.Errorf("CVE data not available")
	}

	cveID = strings.ToUpper(cveID)
	result := make(map[string]interface{})

	var affectedPackages []map[string]interface{}

	for pkgName, packageCVEs := range *s.cveData {
		if cveInfo, exists := packageCVEs[cveID]; exists {
			pkgInfo := map[string]interface{}{
				"package":     pkgName,
				"description": cveInfo.Description,
				"debian_bug":  cveInfo.Debianbug,
				"releases":    cveInfo.Releases,
			}
			affectedPackages = append(affectedPackages, pkgInfo)

			if result["description"] == nil {
				result["description"] = cveInfo.Description
			}
		}
	}

	if len(affectedPackages) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	result["cve_id"] = cveID
	result["affected_packages"] = affectedPackages
	result["affected_count"] = len(affectedPackages)

	return result, nil
}

// GetStatus returns the current status of the CVE scanner
func (s *CVEScanner) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg := s.config.Get()

	// Build list of enabled data sources
	dataSources := []string{"debian"}
	if cfg.CVENVDEnabled {
		dataSources = append(dataSources, "nvd")
	}
	if cfg.CVEOSVEnabled {
		dataSources = append(dataSources, "osv")
	}

	status := map[string]interface{}{
		"initialized":     s.cveData != nil,
		"enabled":         cfg.CVEScannerEnabled,
		"scan_after_sync": cfg.CVEScanAfterSync,
		"data_sources":    dataSources,
		"nvd_enabled":     cfg.CVENVDEnabled,
		"osv_enabled":     cfg.CVEOSVEnabled,
		"cvss_cache_size": len(s.cvssCache),
	}

	if s.cveData != nil {
		status["packages_with_cves"] = len(*s.cveData)
		status["last_updated"] = s.cacheTime
		status["data_age"] = time.Since(s.cacheTime).String()
		status["cache_path"] = s.cachePath
	}

	if s.osvData != nil {
		status["osv_vulnerabilities"] = len(s.osvData.Vulnerabilities)
		status["osv_last_updated"] = s.osvData.LastUpdated
	}

	if s.lastScanResult != nil {
		status["last_scan"] = map[string]interface{}{
			"scan_time":           s.lastScanResult.ScanTime,
			"total_packages":      s.lastScanResult.TotalPackages,
			"vulnerable_packages": s.lastScanResult.VulnerablePackages,
			"total_cves":          s.lastScanResult.TotalCVEs,
			"critical_cves":       s.lastScanResult.CriticalCVEs,
			"high_cves":           s.lastScanResult.HighCVEs,
			"medium_cves":         s.lastScanResult.MediumCVEs,
			"low_cves":            s.lastScanResult.LowCVEs,
		}
	}

	return status
}

// GetLastScanResult returns the last scan result
func (s *CVEScanner) GetLastScanResult() *ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScanResult
}

// IsEnabled returns whether the CVE scanner is enabled
func (s *CVEScanner) IsEnabled() bool {
	cfg := s.config.Get()
	return cfg.CVEScannerEnabled
}

// ShouldScanAfterSync returns whether CVE scan should run after sync
func (s *CVEScanner) ShouldScanAfterSync() bool {
	cfg := s.config.Get()
	return cfg.CVEScannerEnabled && cfg.CVEScanAfterSync
}

// ScanAsInterface wraps Scan to return interface{} for web console compatibility
func (s *CVEScanner) ScanAsInterface(release, component, architecture string, includePackages bool) (interface{}, error) {
	return s.Scan(release, component, architecture, includePackages)
}

// GetPackageCVEsAsInterface wraps GetPackageCVEs to return interface{} for web console compatibility
func (s *CVEScanner) GetPackageCVEsAsInterface(packageName, release string) (interface{}, error) {
	return s.GetPackageCVEs(packageName, release)
}
