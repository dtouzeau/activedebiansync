package cvescanner

// CVEScannerAdapter wraps CVEScanner to implement interfaces with interface{} return types
// This adapter allows CVEScanner to be used with sync.CVEScannerInterface and webconsole.CVEScannerProvider
type CVEScannerAdapter struct {
	scanner *CVEScanner
}

// NewCVEScannerAdapter creates a new adapter wrapping a CVEScanner
func NewCVEScannerAdapter(scanner *CVEScanner) *CVEScannerAdapter {
	return &CVEScannerAdapter{scanner: scanner}
}

// GetStatus returns the CVE scanner status
func (a *CVEScannerAdapter) GetStatus() map[string]interface{} {
	return a.scanner.GetStatus()
}

// UpdateCVEData updates the CVE database
func (a *CVEScannerAdapter) UpdateCVEData() error {
	return a.scanner.UpdateCVEData()
}

// Scan performs a CVE scan and returns the result as interface{}
func (a *CVEScannerAdapter) Scan(release, component, architecture string, includePackages bool) (interface{}, error) {
	return a.scanner.Scan(release, component, architecture, includePackages)
}

// GetPackageCVEs returns CVE information for a package as interface{}
func (a *CVEScannerAdapter) GetPackageCVEs(packageName, release string) (interface{}, error) {
	return a.scanner.GetPackageCVEs(packageName, release)
}

// SearchCVE searches for a specific CVE
func (a *CVEScannerAdapter) SearchCVE(cveID string) (map[string]interface{}, error) {
	return a.scanner.SearchCVE(cveID)
}

// IsEnabled returns whether the CVE scanner is enabled
func (a *CVEScannerAdapter) IsEnabled() bool {
	return a.scanner.IsEnabled()
}

// ShouldScanAfterSync returns whether CVE scan should run after sync
func (a *CVEScannerAdapter) ShouldScanAfterSync() bool {
	return a.scanner.ShouldScanAfterSync()
}

// GetScanner returns the underlying CVEScanner (for cases where concrete type is needed)
func (a *CVEScannerAdapter) GetScanner() *CVEScanner {
	return a.scanner
}
