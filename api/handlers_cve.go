package api

import (
	"activedebiansync/cvescanner"
	"encoding/json"
	"net/http"
	"strconv"
)

// CVEScannerProvider interface for CVE scanning operations
type CVEScannerProvider interface {
	UpdateCVEData() error
	EnsureCVEData() error
	Scan(release, component, architecture string, includePackages bool) (*cvescanner.ScanResult, error)
	GetSummary() (*cvescanner.ScanSummary, error)
	GetPackageCVEs(packageName, release string) (*cvescanner.VulnerablePackage, error)
	SearchCVE(cveID string) (map[string]interface{}, error)
	GetStatus() map[string]interface{}
}

// SetCVEScanner sets the CVE scanner for the API
func (api *RestAPI) SetCVEScanner(scanner CVEScannerProvider) {
	api.cveScanner = scanner
}

// handleCVEStatus returns the status of the CVE scanner
func (api *RestAPI) handleCVEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	status := api.cveScanner.GetStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleCVEUpdate triggers an update of the CVE database
func (api *RestAPI) handleCVEUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	api.logger.LogInfo("API: Triggering CVE database update")

	if err := api.cveScanner.UpdateCVEData(); err != nil {
		api.logger.LogError("Failed to update CVE data: %v", err)
		http.Error(w, "Failed to update CVE data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "CVE database updated successfully",
	})
}

// handleCVEScan performs a CVE scan on the repository
func (api *RestAPI) handleCVEScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	release := query.Get("release")
	component := query.Get("component")
	architecture := query.Get("architecture")

	// Whether to include full package details
	includePackages := false
	if inc := query.Get("include_packages"); inc == "true" || inc == "1" {
		includePackages = true
	}

	// Limit number of packages returned
	limit := 0
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	result, err := api.cveScanner.Scan(release, component, architecture, includePackages)
	if err != nil {
		api.logger.LogError("CVE scan failed: %v", err)
		http.Error(w, "CVE scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply limit if specified
	if includePackages && limit > 0 && len(result.Packages) > limit {
		result.Packages = result.Packages[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleCVESummary returns a summary of CVE status across all releases
func (api *RestAPI) handleCVESummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	summary, err := api.cveScanner.GetSummary()
	if err != nil {
		api.logger.LogError("Failed to get CVE summary: %v", err)
		http.Error(w, "Failed to get CVE summary: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// handleCVEPackage returns CVE information for a specific package
func (api *RestAPI) handleCVEPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	packageName := query.Get("package")
	if packageName == "" {
		packageName = query.Get("name")
	}
	if packageName == "" {
		http.Error(w, "Missing required parameter: package or name", http.StatusBadRequest)
		return
	}

	release := query.Get("release")

	result, err := api.cveScanner.GetPackageCVEs(packageName, release)
	if err != nil {
		if err.Error() == "package not found: "+packageName {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		api.logger.LogError("Failed to get package CVEs: %v", err)
		http.Error(w, "Failed to get package CVEs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleCVESearch searches for information about a specific CVE
func (api *RestAPI) handleCVESearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	cveID := query.Get("cve")
	if cveID == "" {
		cveID = query.Get("id")
	}
	if cveID == "" {
		cveID = query.Get("q")
	}
	if cveID == "" {
		http.Error(w, "Missing required parameter: cve, id, or q", http.StatusBadRequest)
		return
	}

	result, err := api.cveScanner.SearchCVE(cveID)
	if err != nil {
		if err.Error() == "CVE not found: "+cveID {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		api.logger.LogError("Failed to search CVE: %v", err)
		http.Error(w, "Failed to search CVE: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleCVEVulnerable returns only vulnerable packages (with CVEs)
func (api *RestAPI) handleCVEVulnerable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	release := query.Get("release")
	component := query.Get("component")
	architecture := query.Get("architecture")

	// Filter by urgency
	urgency := query.Get("urgency") // critical, high, medium, low

	// Limit
	limit := 100
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	result, err := api.cveScanner.Scan(release, component, architecture, true)
	if err != nil {
		api.logger.LogError("CVE scan failed: %v", err)
		http.Error(w, "CVE scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter by urgency if specified
	if urgency != "" {
		var filtered []cvescanner.VulnerablePackage
		for _, pkg := range result.Packages {
			switch urgency {
			case "critical":
				if pkg.Critical > 0 {
					filtered = append(filtered, pkg)
				}
			case "high":
				if pkg.High > 0 || pkg.Critical > 0 {
					filtered = append(filtered, pkg)
				}
			case "medium":
				if pkg.Medium > 0 || pkg.High > 0 || pkg.Critical > 0 {
					filtered = append(filtered, pkg)
				}
			case "low":
				filtered = append(filtered, pkg)
			}
		}
		result.Packages = filtered
		result.VulnerablePackages = len(filtered)
	}

	// Apply limit
	if len(result.Packages) > limit {
		result.Packages = result.Packages[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_time":             result.ScanTime,
		"release":               release,
		"component":             component,
		"architecture":          architecture,
		"urgency_filter":        urgency,
		"vulnerable_count":      result.VulnerablePackages,
		"total_cves":            result.TotalCVEs,
		"cve_data_last_updated": result.CVEDataLastUpdated,
		"packages":              result.Packages,
	})
}
