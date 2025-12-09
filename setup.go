package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultConfigDir   = "/etc/ActiveDebianSync"
	defaultConfigFile  = "/etc/ActiveDebianSync/config.json"
	defaultRepoPath    = "/var/lib/ActiveDebianSync/mirror"
	defaultLogPath     = "/var/log/ActiveDebianSync/sync.log"
	defaultAccessLog   = "/var/log/ActiveDebianSync/access.log"
	defaultPIDFile     = "/run/ActiveDebianSync.pid"
	defaultUser        = "ActiveDebianSync"
	defaultGroup       = "ActiveDebianSync"
	systemdServiceFile = "/etc/systemd/system/activedebiansync.service"
	systemdServiceName = "activedebiansync"
)

// SetupConfig holds the setup configuration
type SetupConfig struct {
	RepositoryPath string
	Username       string
	GroupName      string
	ConfigDir      string
	HTTPPort       int
	HTTPSPort      int
	WebConsolePort int
}

// runSetup runs the interactive setup wizard
func runSetup() {
	fmt.Println("=========================================")
	fmt.Printf("  %s Setup Wizard\n", AppName)
	fmt.Println("=========================================")
	fmt.Println()

	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("Error: Setup must be run as root")
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)

	// Check if already installed
	if _, err := os.Stat(defaultConfigFile); err == nil {
		fmt.Println("Warning: Configuration file already exists at", defaultConfigFile)
		fmt.Print("Do you want to overwrite it? [y/N]: ")
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Setup cancelled.")
			os.Exit(0)
		}
	}

	cfg := SetupConfig{
		RepositoryPath: defaultRepoPath,
		Username:       defaultUser,
		GroupName:      defaultGroup,
		ConfigDir:      defaultConfigDir,
		HTTPPort:       8080,
		HTTPSPort:      8443,
		WebConsolePort: 8090,
	}

	// Ask for repository path
	fmt.Printf("\nRepository path [%s]: ", defaultRepoPath)
	repoPath, _ := reader.ReadString('\n')
	repoPath = strings.TrimSpace(repoPath)
	if repoPath != "" {
		cfg.RepositoryPath = repoPath
	}

	// Ask for HTTP port
	fmt.Printf("HTTP port [%d]: ", cfg.HTTPPort)
	httpPortStr, _ := reader.ReadString('\n')
	httpPortStr = strings.TrimSpace(httpPortStr)
	if httpPortStr != "" {
		if port, err := strconv.Atoi(httpPortStr); err == nil && port > 0 && port < 65536 {
			cfg.HTTPPort = port
		}
	}

	// Ask for Web Console port
	fmt.Printf("Web Console port [%d]: ", cfg.WebConsolePort)
	wcPortStr, _ := reader.ReadString('\n')
	wcPortStr = strings.TrimSpace(wcPortStr)
	if wcPortStr != "" {
		if port, err := strconv.Atoi(wcPortStr); err == nil && port > 0 && port < 65536 {
			cfg.WebConsolePort = port
		}
	}

	fmt.Println("\n--- Setup Summary ---")
	fmt.Printf("Repository path: %s\n", cfg.RepositoryPath)
	fmt.Printf("HTTP port: %d\n", cfg.HTTPPort)
	fmt.Printf("Web Console port: %d\n", cfg.WebConsolePort)
	fmt.Printf("User/Group: %s/%s\n", cfg.Username, cfg.GroupName)
	fmt.Printf("Config directory: %s\n", cfg.ConfigDir)
	fmt.Printf("PID file: %s\n", defaultPIDFile)
	fmt.Println()

	fmt.Print("Proceed with installation? [Y/n]: ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm == "n" || confirm == "no" {
		fmt.Println("Setup cancelled.")
		os.Exit(0)
	}

	// Perform setup
	if err := performSetup(cfg); err != nil {
		fmt.Printf("\nError during setup: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=========================================")
	fmt.Println("  Setup completed successfully!")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Edit configuration: %s\n", defaultConfigFile)
	fmt.Printf("  2. Start the service: systemctl start %s\n", systemdServiceName)
	fmt.Printf("  3. Enable on boot: systemctl enable %s\n", systemdServiceName)
	fmt.Printf("  4. Access Web Console: http://localhost:%d\n", cfg.WebConsolePort)
	fmt.Println("     Default credentials: admin / admin")
	fmt.Println()
}

func performSetup(cfg SetupConfig) error {
	fmt.Println("\n[1/6] Creating user and group...")
	if err := createUserAndGroup(cfg.Username, cfg.GroupName); err != nil {
		return fmt.Errorf("failed to create user/group: %w", err)
	}

	fmt.Println("[2/6] Creating directories...")
	if err := createDirectories(cfg); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	fmt.Println("[3/6] Creating configuration file...")
	if err := createConfigFile(cfg); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	fmt.Println("[4/6] Installing binary...")
	if err := installBinary(); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}

	fmt.Println("[5/6] Creating systemd service...")
	if err := createSystemdService(cfg); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	fmt.Println("[6/6] Reloading systemd...")
	if err := reloadSystemd(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	return nil
}

func createUserAndGroup(username, groupname string) error {
	// Check if group exists
	if _, err := user.LookupGroup(groupname); err != nil {
		// Create group
		cmd := exec.Command("groupadd", "--system", groupname)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("groupadd failed: %s - %w", string(output), err)
		}
		fmt.Printf("    Created group: %s\n", groupname)
	} else {
		fmt.Printf("    Group already exists: %s\n", groupname)
	}

	// Check if user exists
	if _, err := user.Lookup(username); err != nil {
		// Create user
		cmd := exec.Command("useradd",
			"--system",
			"--gid", groupname,
			"--no-create-home",
			"--shell", "/usr/sbin/nologin",
			"--comment", "ActiveDebianSync Service",
			username)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("useradd failed: %s - %w", string(output), err)
		}
		fmt.Printf("    Created user: %s\n", username)
	} else {
		fmt.Printf("    User already exists: %s\n", username)
	}

	return nil
}

func createDirectories(cfg SetupConfig) error {
	directories := []struct {
		path  string
		owner string
		group string
		mode  os.FileMode
	}{
		{cfg.ConfigDir, "root", "root", 0755},
		{cfg.RepositoryPath, cfg.Username, cfg.GroupName, 0755},
		{filepath.Dir(defaultLogPath), cfg.Username, cfg.GroupName, 0755},
	}

	for _, dir := range directories {
		if err := os.MkdirAll(dir.path, dir.mode); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir.path, err)
		}

		// Change ownership
		u, err := user.Lookup(dir.owner)
		if err != nil {
			continue // Skip if user not found (will be owned by root)
		}
		g, err := user.LookupGroup(dir.group)
		if err != nil {
			continue
		}

		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(dir.path, uid, gid); err != nil {
			fmt.Printf("    Warning: couldn't change ownership of %s: %v\n", dir.path, err)
		}

		fmt.Printf("    Created: %s\n", dir.path)
	}

	return nil
}

func createConfigFile(cfg SetupConfig) error {
	config := map[string]interface{}{
		"repository_path":           cfg.RepositoryPath,
		"log_path":                  defaultLogPath,
		"access_log_path":           defaultAccessLog,
		"pid_file":                  defaultPIDFile,
		"run_as_user":               cfg.Username,
		"run_as_group":              cfg.GroupName,
		"http_enabled":              true,
		"http_port":                 cfg.HTTPPort,
		"http_listen_addr":          "0.0.0.0",
		"https_enabled":             false,
		"https_port":                cfg.HTTPSPort,
		"api_enabled":               true,
		"api_port":                  9090,
		"api_listen_addr":           "127.0.0.1",
		"web_console_enabled":       true,
		"web_console_port":          cfg.WebConsolePort,
		"web_console_listen_addr":   "0.0.0.0",
		"web_console_https_enabled": false,
		"sync_interval":             60,
		"sync_releases": []string{
			"bookworm",
			"bookworm-updates",
			"bookworm-security",
		},
		"sync_components":            []string{"main", "contrib"},
		"sync_architectures":         []string{"amd64"},
		"max_disk_usage_percent":     90,
		"download_bandwidth_limit":   0,
		"parallel_downloads":         4,
		"parallel_downloads_enabled": true,
		"integrity_check_enabled":    true,
		"rate_limit_enabled":         true,
		"rate_limit_requests":        100,
		"rate_limit_window":          60,
		"cve_scanner_enabled":        false,
		"package_search_enabled":     true,
		"sync_contents":              true,
	}

	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(defaultConfigFile, data, 0644); err != nil {
		return err
	}

	fmt.Printf("    Created: %s\n", defaultConfigFile)
	return nil
}

func installBinary() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	destPath := "/usr/local/bin/activedebiansync"

	// If already at destination, skip
	if execPath == destPath {
		fmt.Printf("    Binary already at: %s\n", destPath)
		return nil
	}

	// Copy binary
	input, err := os.ReadFile(execPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(destPath, input, 0755); err != nil {
		return err
	}

	fmt.Printf("    Installed: %s\n", destPath)
	return nil
}

func createSystemdService(cfg SetupConfig) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=ActiveDebianSync - Debian Repository Mirror
Documentation=https://github.com/activedebiansync
After=network.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart=/usr/local/bin/activedebiansync -config %s
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=%s
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s %s %s /run
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, cfg.Username, cfg.GroupName, defaultConfigFile, defaultPIDFile,
		cfg.RepositoryPath, filepath.Dir(defaultLogPath), cfg.ConfigDir)

	if err := os.WriteFile(systemdServiceFile, []byte(serviceContent), 0644); err != nil {
		return err
	}

	fmt.Printf("    Created: %s\n", systemdServiceFile)
	return nil
}

func reloadSystemd() error {
	cmd := exec.Command("systemctl", "daemon-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %s - %w", string(output), err)
	}
	fmt.Println("    Systemd daemon reloaded")
	return nil
}

// runUninstall removes the service and configuration
func runUninstall() {
	fmt.Println("=========================================")
	fmt.Printf("  %s Uninstall\n", AppName)
	fmt.Println("=========================================")
	fmt.Println()

	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("Error: Uninstall must be run as root")
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("This will remove:")
	fmt.Printf("  - Systemd service: %s\n", systemdServiceFile)
	fmt.Printf("  - Configuration: %s\n", defaultConfigDir)
	fmt.Printf("  - Binary: /usr/local/bin/activedebiansync\n")
	fmt.Printf("  - User: %s\n", defaultUser)
	fmt.Printf("  - Group: %s\n", defaultGroup)
	fmt.Println()
	fmt.Println("NOTE: Repository data and logs will NOT be removed.")
	fmt.Println()

	fmt.Print("Are you sure you want to uninstall? [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Uninstall cancelled.")
		os.Exit(0)
	}

	fmt.Print("Also remove repository data? [y/N]: ")
	removeData, _ := reader.ReadString('\n')
	removeData = strings.TrimSpace(strings.ToLower(removeData))
	removeRepoData := removeData == "y" || removeData == "yes"

	if err := performUninstall(removeRepoData); err != nil {
		fmt.Printf("\nError during uninstall: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=========================================")
	fmt.Println("  Uninstall completed successfully!")
	fmt.Println("=========================================")
}

func performUninstall(removeRepoData bool) error {
	fmt.Println("\n[1/5] Stopping service...")
	stopService()

	fmt.Println("[2/5] Disabling service...")
	disableService()

	fmt.Println("[3/5] Removing systemd service...")
	if err := os.Remove(systemdServiceFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    Warning: couldn't remove %s: %v\n", systemdServiceFile, err)
	} else if err == nil {
		fmt.Printf("    Removed: %s\n", systemdServiceFile)
	}

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("[4/5] Removing files...")
	// Remove config directory
	if err := os.RemoveAll(defaultConfigDir); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    Warning: couldn't remove %s: %v\n", defaultConfigDir, err)
	} else if err == nil {
		fmt.Printf("    Removed: %s\n", defaultConfigDir)
	}

	// Remove binary
	binPath := "/usr/local/bin/activedebiansync"
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    Warning: couldn't remove %s: %v\n", binPath, err)
	} else if err == nil {
		fmt.Printf("    Removed: %s\n", binPath)
	}

	// Remove PID file
	if err := os.Remove(defaultPIDFile); err != nil && !os.IsNotExist(err) {
		// Ignore
	}

	// Optionally remove repository data
	if removeRepoData {
		fmt.Println("    Removing repository data...")
		if err := os.RemoveAll(defaultRepoPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    Warning: couldn't remove %s: %v\n", defaultRepoPath, err)
		} else if err == nil {
			fmt.Printf("    Removed: %s\n", defaultRepoPath)
		}

		// Remove log directory
		logDir := filepath.Dir(defaultLogPath)
		if err := os.RemoveAll(logDir); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    Warning: couldn't remove %s: %v\n", logDir, err)
		} else if err == nil {
			fmt.Printf("    Removed: %s\n", logDir)
		}
	}

	fmt.Println("[5/5] Removing user and group...")
	removeUserAndGroup()

	return nil
}

func stopService() {
	cmd := exec.Command("systemctl", "stop", systemdServiceName)
	if err := cmd.Run(); err != nil {
		fmt.Printf("    Service not running or couldn't stop\n")
	} else {
		fmt.Printf("    Stopped: %s\n", systemdServiceName)
	}
}

func disableService() {
	cmd := exec.Command("systemctl", "disable", systemdServiceName)
	if err := cmd.Run(); err != nil {
		fmt.Printf("    Service not enabled or couldn't disable\n")
	} else {
		fmt.Printf("    Disabled: %s\n", systemdServiceName)
	}
}

func removeUserAndGroup() {
	// Remove user
	cmd := exec.Command("userdel", defaultUser)
	if err := cmd.Run(); err != nil {
		fmt.Printf("    User %s not found or couldn't remove\n", defaultUser)
	} else {
		fmt.Printf("    Removed user: %s\n", defaultUser)
	}

	// Remove group
	cmd = exec.Command("groupdel", defaultGroup)
	if err := cmd.Run(); err != nil {
		fmt.Printf("    Group %s not found or couldn't remove\n", defaultGroup)
	} else {
		fmt.Printf("    Removed group: %s\n", defaultGroup)
	}
}
