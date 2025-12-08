package main

import (
	"activedebiansync/config"
	"activedebiansync/cvescanner"
	"activedebiansync/utils"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

func handleCVECommand() {
	if len(os.Args) < 3 {
		printCVEHelp()
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "scan":
		handleCVEScan()
	case "update":
		handleCVEUpdate()
	case "status":
		handleCVEStatus()
	case "package":
		handleCVEPackageLookup()
	case "search":
		handleCVESearchCmd()
	case "summary":
		handleCVESummary()
	case "help":
		printCVEHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown CVE subcommand: %s\n", subcommand)
		printCVEHelp()
		os.Exit(1)
	}
}

func printCVEHelp() {
	fmt.Println("CVE Scanner - Scan repository packages for known vulnerabilities")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  %s cve <command> [options]\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  scan      Scan repository for CVEs")
	fmt.Println("  update    Update CVE database from Debian Security Tracker")
	fmt.Println("  status    Show CVE scanner status")
	fmt.Println("  package   Look up CVEs for a specific package")
	fmt.Println("  search    Search for a specific CVE ID")
	fmt.Println("  summary   Show summary of CVEs across all releases")
	fmt.Println("  help      Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Update CVE database")
	fmt.Printf("  %s cve update\n\n", os.Args[0])
	fmt.Println("  # Scan all packages for CVEs")
	fmt.Printf("  %s cve scan\n\n", os.Args[0])
	fmt.Println("  # Scan specific release")
	fmt.Printf("  %s cve scan -release bookworm\n\n", os.Args[0])
	fmt.Println("  # Show only high/critical CVEs")
	fmt.Printf("  %s cve scan -urgency high\n\n", os.Args[0])
	fmt.Println("  # Look up CVEs for a package")
	fmt.Printf("  %s cve package -name openssl\n\n", os.Args[0])
	fmt.Println("  # Search for a specific CVE")
	fmt.Printf("  %s cve search -cve CVE-2024-1234\n\n", os.Args[0])
	fmt.Println("  # Get vulnerability summary")
	fmt.Printf("  %s cve summary\n", os.Args[0])
}

var cveConfigPath string

func initCVEScanner() (*cvescanner.CVEScanner, error) {
	configPath := config.DefaultConfigPath

	// Use global config path if set
	if cveConfigPath != "" {
		configPath = cveConfigPath
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create a minimal logger that writes to stderr
	logger := &utils.Logger{}

	return cvescanner.NewCVEScanner(cfg, logger), nil
}

func handleCVEScan() {
	fs := flag.NewFlagSet("cve scan", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	release := fs.String("release", "", "Filter by release (e.g., bookworm)")
	component := fs.String("component", "", "Filter by component (e.g., main)")
	arch := fs.String("arch", "", "Filter by architecture (e.g., amd64)")
	urgency := fs.String("urgency", "", "Filter by minimum urgency (critical, high, medium, low)")
	limit := fs.Int("limit", 0, "Limit number of results (0 = unlimited)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	verbose := fs.Bool("v", false, "Verbose output (show all CVE details)")

	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Scanning repository for CVEs...")

	result, err := scanner.Scan(*release, *component, *arch, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Filter by urgency if specified
	if *urgency != "" {
		var filtered []cvescanner.VulnerablePackage
		for _, pkg := range result.Packages {
			switch strings.ToLower(*urgency) {
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
	if *limit > 0 && len(result.Packages) > *limit {
		result.Packages = result.Packages[:*limit]
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	// Text output
	fmt.Println()
	fmt.Printf("CVE Scan Results\n")
	fmt.Printf("================\n")
	fmt.Printf("Scan Time:           %s\n", result.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("CVE Data Updated:    %s\n", result.CVEDataLastUpdated.Format("2006-01-02 15:04:05"))
	fmt.Printf("Total Packages:      %d\n", result.TotalPackages)
	fmt.Printf("Vulnerable Packages: %d\n", result.VulnerablePackages)
	fmt.Printf("Total CVEs:          %d\n", result.TotalCVEs)
	fmt.Println()

	if result.TotalCVEs > 0 {
		fmt.Printf("CVEs by Urgency:\n")
		fmt.Printf("  Critical: %d\n", result.CriticalCVEs)
		fmt.Printf("  High:     %d\n", result.HighCVEs)
		fmt.Printf("  Medium:   %d\n", result.MediumCVEs)
		fmt.Printf("  Low:      %d\n", result.LowCVEs)
		fmt.Printf("  Other:    %d\n", result.UnassignedCVEs)
		fmt.Println()
	}

	if len(result.Packages) > 0 {
		fmt.Printf("Vulnerable Packages:\n")
		fmt.Println(strings.Repeat("-", 100))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "PACKAGE\tVERSION\tRELEASE\tCVEs\tCRIT\tHIGH\tMED\tLOW\n")

		for _, pkg := range result.Packages {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
				pkg.Package, pkg.Version, pkg.Release,
				pkg.TotalCVEs, pkg.Critical, pkg.High, pkg.Medium, pkg.Low)

			if *verbose {
				for _, cve := range pkg.CVEs {
					desc := cve.Description
					if len(desc) > 60 {
						desc = desc[:60] + "..."
					}
					fmt.Fprintf(w, "  -> %s\t[%s]\t%s\n", cve.CVEID, cve.Urgency, desc)
				}
			}
		}
		w.Flush()
	} else {
		fmt.Println("No vulnerable packages found!")
	}
}

func handleCVEUpdate() {
	fs := flag.NewFlagSet("cve update", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Updating CVE database from Debian Security Tracker...")

	if err := scanner.UpdateCVEData(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CVE database updated successfully!")
}

func handleCVEStatus() {
	fs := flag.NewFlagSet("cve status", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Try to load cached data
	_ = scanner.EnsureCVEData()

	status := scanner.GetStatus()

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(status)
		return
	}

	fmt.Println("CVE Scanner Status")
	fmt.Println("==================")

	if initialized, ok := status["initialized"].(bool); ok && initialized {
		fmt.Printf("Status:        Initialized\n")
		if count, ok := status["packages_with_cves"].(int); ok {
			fmt.Printf("Packages:      %d (with CVE info)\n", count)
		}
		if lastUpdated, ok := status["last_updated"]; ok {
			fmt.Printf("Last Updated:  %v\n", lastUpdated)
		}
		if age, ok := status["data_age"].(string); ok {
			fmt.Printf("Data Age:      %s\n", age)
		}
		if cachePath, ok := status["cache_path"].(string); ok {
			fmt.Printf("Cache Path:    %s\n", cachePath)
		}
	} else {
		fmt.Println("Status: Not initialized")
		fmt.Println("Run 'cve update' to fetch CVE data")
	}
}

func handleCVEPackageLookup() {
	fs := flag.NewFlagSet("cve package", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	name := fs.String("name", "", "Package name (required)")
	release := fs.String("release", "", "Filter by release")
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	if *name == "" {
		fmt.Fprintln(os.Stderr, "Error: -name is required")
		fs.Usage()
		os.Exit(1)
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result, err := scanner.GetPackageCVEs(*name, *release)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	fmt.Printf("CVE Information for %s\n", result.Package)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Version:      %s\n", result.Version)
	fmt.Printf("Release:      %s\n", result.Release)
	fmt.Printf("Component:    %s\n", result.Component)
	fmt.Printf("Architecture: %s\n", result.Architecture)
	fmt.Printf("Total CVEs:   %d\n", result.TotalCVEs)
	fmt.Println()

	if result.TotalCVEs > 0 {
		fmt.Printf("CVE Breakdown:\n")
		fmt.Printf("  Critical: %d\n", result.Critical)
		fmt.Printf("  High:     %d\n", result.High)
		fmt.Printf("  Medium:   %d\n", result.Medium)
		fmt.Printf("  Low:      %d\n", result.Low)
		fmt.Println()

		fmt.Println("CVE Details:")
		fmt.Println(strings.Repeat("-", 80))

		for _, cve := range result.CVEs {
			fmt.Printf("\n%s [%s]\n", cve.CVEID, strings.ToUpper(cve.Urgency))
			fmt.Printf("  Status: %s\n", cve.Status)
			if cve.FixedVersion != "" {
				fmt.Printf("  Fixed in: %s\n", cve.FixedVersion)
			}
			if cve.DebianBug > 0 {
				fmt.Printf("  Debian Bug: #%d\n", cve.DebianBug)
			}
			desc := cve.Description
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
			fmt.Printf("  %s\n", desc)
		}
	} else {
		fmt.Println("No known CVEs for this package.")
	}
}

func handleCVESearchCmd() {
	fs := flag.NewFlagSet("cve search", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	cveID := fs.String("cve", "", "CVE ID to search (e.g., CVE-2024-1234)")
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	if *cveID == "" {
		// Check if CVE ID was passed as positional argument
		if fs.NArg() > 0 {
			*cveID = fs.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "Error: CVE ID is required")
			fmt.Fprintln(os.Stderr, "Usage: cve search -cve CVE-2024-1234")
			os.Exit(1)
		}
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result, err := scanner.SearchCVE(*cveID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	fmt.Printf("CVE: %s\n", result["cve_id"])
	fmt.Println(strings.Repeat("=", 60))

	if desc, ok := result["description"].(string); ok && desc != "" {
		fmt.Printf("\nDescription:\n%s\n", desc)
	}

	if count, ok := result["affected_count"].(int); ok {
		fmt.Printf("\nAffected Packages: %d\n", count)
	}

	if packages, ok := result["affected_packages"].([]map[string]interface{}); ok {
		fmt.Println("\nPackage Details:")
		fmt.Println(strings.Repeat("-", 60))

		for _, pkg := range packages {
			fmt.Printf("\nPackage: %s\n", pkg["package"])

			if releases, ok := pkg["releases"].(map[string]cvescanner.ReleaseStatus); ok {
				for relName, relStatus := range releases {
					fmt.Printf("  %s:\n", relName)
					fmt.Printf("    Status:  %s\n", relStatus.Status)
					fmt.Printf("    Urgency: %s\n", relStatus.Urgency)
					if relStatus.FixedVersion != "" {
						fmt.Printf("    Fixed:   %s\n", relStatus.FixedVersion)
					}
				}
			}
		}
	}
}

func handleCVESummary() {
	fs := flag.NewFlagSet("cve summary", flag.ExitOnError)
	configFlag := fs.String("config", "", "Path to configuration file")
	jsonOutput := fs.Bool("json", false, "Output as JSON")
	fs.Parse(os.Args[3:])

	if *configFlag != "" {
		cveConfigPath = *configFlag
	}

	scanner, err := initCVEScanner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Generating CVE summary...")

	summary, err := scanner.GetSummary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
		return
	}

	fmt.Println()
	fmt.Println("CVE Summary Report")
	fmt.Println("==================")
	fmt.Printf("Generated:           %s\n", summary.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("CVE Data Updated:    %s\n", summary.CVEDataLastUpdated.Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Printf("Total Packages:      %d\n", summary.TotalPackages)
	fmt.Printf("Vulnerable Packages: %d\n", summary.VulnerablePackages)
	fmt.Printf("Total CVEs:          %d\n", summary.TotalCVEs)
	fmt.Println()

	fmt.Println("CVEs by Urgency:")
	fmt.Printf("  Critical:   %d\n", summary.ByUrgency["critical"])
	fmt.Printf("  High:       %d\n", summary.ByUrgency["high"])
	fmt.Printf("  Medium:     %d\n", summary.ByUrgency["medium"])
	fmt.Printf("  Low:        %d\n", summary.ByUrgency["low"])
	fmt.Printf("  Unassigned: %d\n", summary.ByUrgency["unassigned"])
	fmt.Println()

	if len(summary.ByRelease) > 0 {
		fmt.Println("CVEs by Release:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  RELEASE\tPACKAGES\tVULNERABLE\tCVEs\n")
		for release, stats := range summary.ByRelease {
			fmt.Fprintf(w, "  %s\t%d\t%d\t%d\n",
				release, stats.TotalPackages, stats.VulnerablePackages, stats.TotalCVEs)
		}
		w.Flush()
		fmt.Println()
	}

	if len(summary.TopVulnerable) > 0 {
		fmt.Println("Top Vulnerable Packages:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  PACKAGE\tVERSION\tRELEASE\tCVEs\tMAX URGENCY\n")
		for _, pkg := range summary.TopVulnerable {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%s\n",
				pkg.Package, pkg.Version, pkg.Release, pkg.CVECount, pkg.MaxUrgency)
		}
		w.Flush()
	}
}
