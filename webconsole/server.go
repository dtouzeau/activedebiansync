package webconsole

import (
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"
)

// HTTPServerProvider interface for HTTP server
type HTTPServerProvider interface {
	GetStats() interface{}
}

// SyncerProvider interface for sync operations
type SyncerProvider interface {
	GetStats() interface{}
	Sync()
	IsRunning() bool
}

// PackageManagerProvider interface for package manager
type PackageManagerProvider interface {
	AddPackage(debPath, release, component, architecture string) error
}

// CVEScannerProvider interface for CVE scanning
type CVEScannerProvider interface {
	GetStatus() map[string]interface{}
	UpdateCVEData() error
	Scan(release, component, architecture string, includePackages bool) (interface{}, error)
	GetPackageCVEs(packageName, release string) (interface{}, error)
	SearchCVE(cveID string) (map[string]interface{}, error)
	IsEnabled() bool
}

// WebConsole manages the web console server
type WebConsole struct {
	config        *config.Config
	configPath    string
	configDirName string
	logger        *utils.Logger
	usersDB       *database.UsersDB
	server        *http.Server
	httpServer    interface{}
	syncer        interface{}
	pkgManager    interface{}
	cveScanner    CVEScannerProvider
	templates     *template.Template
	sessionSecret string
	mu            sync.RWMutex
}

// TemplateData holds data for template rendering
type TemplateData struct {
	Title       string
	User        *database.Session
	Page        string
	Data        interface{}
	Flash       string
	FlashType   string
	Version     string
	CurrentYear int
}

// NewWebConsole creates a new WebConsole instance
func NewWebConsole(cfg *config.Config, configPath string, logger *utils.Logger) (*WebConsole, error) {
	cfgData := cfg.Get()

	// Initialize users database
	usersDB, err := database.NewUsersDB(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize users database: %w", err)
	}

	// Generate or use session secret
	sessionSecret := cfgData.WebConsoleSessionSecret
	if sessionSecret == "" {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate session secret: %w", err)
		}
		sessionSecret = hex.EncodeToString(bytes)
	}

	wc := &WebConsole{
		config:        cfg,
		configPath:    configPath,
		configDirName: filepath.Base(filepath.Dir(configPath)),
		logger:        logger,
		usersDB:       usersDB,
		sessionSecret: sessionSecret,
	}

	return wc, nil
}

// SetProviders sets the stats, sync and package providers
func (wc *WebConsole) SetProviders(httpServer, syncer, pkgManager interface{}) {
	wc.httpServer = httpServer
	wc.syncer = syncer
	wc.pkgManager = pkgManager
}

// SetCVEScanner sets the CVE scanner provider
func (wc *WebConsole) SetCVEScanner(scanner CVEScannerProvider) {
	wc.cveScanner = scanner
}

// Start starts the web console server
func (wc *WebConsole) Start(ctx context.Context) error {
	cfg := wc.config.Get()

	if !cfg.WebConsoleEnabled {
		wc.logger.LogInfo("Web Console is disabled")
		return nil
	}

	// Load templates
	if err := wc.loadTemplates(); err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// Static files from assets directory
	// Use config directory name as the web root path prefix
	configDir := filepath.Dir(wc.configPath)
	configDirName := filepath.Base(configDir)

	// Look for assets directory relative to the executable or config
	staticPath := filepath.Join(configDir, "assets")
	if _, err := os.Stat(staticPath); os.IsNotExist(err) {
		// Try relative to executable location
		if execPath, err := os.Executable(); err == nil {
			staticPath = filepath.Join(filepath.Dir(execPath), "assets")
		}
	}

	if _, err := os.Stat(staticPath); err == nil {
		fileServer := http.FileServer(http.Dir(staticPath))
		// Use config directory name as the root path (e.g., /ActiveDebianSync/*)
		mux.Handle("/"+configDirName+"/", http.StripPrefix("/"+configDirName+"/", fileServer))
		// Also keep /static/ for backwards compatibility
		mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	}

	// Public routes
	mux.HandleFunc("/login", wc.handleLogin)
	mux.HandleFunc("/logout", wc.handleLogout)

	// Protected routes
	mux.HandleFunc("/", wc.requireAuth(wc.handleDashboard))
	mux.HandleFunc("/dashboard", wc.requireAuth(wc.handleDashboard))
	mux.HandleFunc("/settings", wc.requireAuth(wc.handleSettings))
	mux.HandleFunc("/packages", wc.requireAuth(wc.handlePackages))
	mux.HandleFunc("/packages/upload", wc.requireAuth(wc.handlePackageUpload))
	mux.HandleFunc("/events", wc.requireAuth(wc.handleEvents))
	mux.HandleFunc("/search", wc.requireAuth(wc.handleSearch))
	mux.HandleFunc("/logs", wc.requireAuth(wc.handleLogs))
	mux.HandleFunc("/users", wc.requireAuth(wc.requireAdmin(wc.handleUsers)))
	mux.HandleFunc("/cve", wc.requireAuth(wc.handleCVE))
	mux.HandleFunc("/cve/find", wc.requireAuth(wc.handleCVEFind))
	mux.HandleFunc("/sync/trigger", wc.requireAuth(wc.handleSyncTrigger))

	// API routes for web console
	mux.HandleFunc("/api/console/stats", wc.requireAuth(wc.handleAPIStats))
	mux.HandleFunc("/api/console/sync/status", wc.requireAuth(wc.handleAPISyncStatus))
	mux.HandleFunc("/api/console/users", wc.requireAuth(wc.requireAdmin(wc.handleAPIUsers)))
	mux.HandleFunc("/api/console/users/create", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserCreate)))
	mux.HandleFunc("/api/console/users/update", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserUpdate)))
	mux.HandleFunc("/api/console/users/delete", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserDelete)))
	mux.HandleFunc("/api/console/users/password", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserPassword)))
	mux.HandleFunc("/api/console/config", wc.requireAuth(wc.requireAdmin(wc.handleAPIConfig)))
	mux.HandleFunc("/api/console/config/update", wc.requireAuth(wc.requireAdmin(wc.handleAPIConfigUpdate)))
	mux.HandleFunc("/api/updates/packages/recent", wc.requireAuth(wc.handleAPIRecentUpdates))
	mux.HandleFunc("/api/search/package", wc.requireAuth(wc.handleAPISearchPackage))
	mux.HandleFunc("/api/search/file", wc.requireAuth(wc.handleAPISearchFile))
	mux.HandleFunc("/api/search/package-files", wc.requireAuth(wc.handleAPIPackageFiles))
	mux.HandleFunc("/api/logs", wc.requireAuth(wc.handleAPILogs))

	// CVE API routes
	mux.HandleFunc("/api/console/cve/status", wc.requireAuth(wc.handleAPICVEStatus))
	mux.HandleFunc("/api/console/cve/update", wc.requireAuth(wc.handleAPICVEUpdate))
	mux.HandleFunc("/api/console/cve/scan", wc.requireAuth(wc.handleAPICVEScan))
	mux.HandleFunc("/api/console/cve/vulnerable", wc.requireAuth(wc.handleAPICVEVulnerable))
	mux.HandleFunc("/api/console/cve/package", wc.requireAuth(wc.handleAPICVEPackage))
	mux.HandleFunc("/api/console/cve/search", wc.requireAuth(wc.handleAPICVESearch))

	addr := fmt.Sprintf("%s:%d", cfg.WebConsoleListenAddr, cfg.WebConsolePort)
	wc.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start session cleanup goroutine
	go wc.cleanupSessions(ctx)

	go func() {
		var err error
		if cfg.WebConsoleHTTPSEnabled {
			// Déterminer les fichiers de certificat à utiliser
			certFile := cfg.WebConsoleTLSCertFile
			keyFile := cfg.WebConsoleTLSKeyFile

			// Si configuré pour utiliser le certificat du serveur HTTP
			if cfg.WebConsoleTLSUseServerCert {
				certFile = cfg.TLSCertFile
				keyFile = cfg.TLSKeyFile
				wc.logger.LogInfo("Starting Web Console HTTPS on %s (using server certificate)", addr)
			} else {
				wc.logger.LogInfo("Starting Web Console HTTPS on %s (using console certificate)", addr)
			}

			err = wc.server.ListenAndServeTLS(certFile, keyFile)
		} else {
			wc.logger.LogInfo("Starting Web Console HTTP on %s", addr)
			err = wc.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			wc.logger.LogError("Web Console server error: %v", err)
		}
	}()

	<-ctx.Done()
	return wc.Stop()
}

// Stop stops the web console server
func (wc *WebConsole) Stop() error {
	if wc.server == nil {
		return nil
	}

	wc.logger.LogInfo("Stopping Web Console server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if wc.usersDB != nil {
		wc.usersDB.Close()
	}

	return wc.server.Shutdown(ctx)
}

// loadTemplates loads HTML templates
func (wc *WebConsole) loadTemplates() error {
	funcMap := template.FuncMap{
		"formatBytes": func(bytes int64) string {
			return utils.FormatBytes(uint64(bytes))
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(d time.Duration) string {
			return d.String()
		},
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	wc.templates = template.New("").Funcs(funcMap)

	// Templates will be embedded or loaded from disk
	// For now, we'll create them inline
	return nil
}

// cleanupSessions periodically cleans up expired sessions
func (wc *WebConsole) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if wc.usersDB != nil {
				if cleaned, err := wc.usersDB.CleanExpiredSessions(); err == nil && cleaned > 0 {
					wc.logger.LogInfo("Cleaned %d expired sessions", cleaned)
				}
			}
		}
	}
}

// getSession retrieves the current session from cookie
func (wc *WebConsole) getSession(r *http.Request) *database.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	session, err := wc.usersDB.GetSession(cookie.Value)
	if err != nil || session == nil {
		return nil
	}

	// Extend session on each request
	cfg := wc.config.Get()
	wc.usersDB.ExtendSession(session.ID, cfg.WebConsoleSessionTimeout)

	return session
}

// setSession sets the session cookie
func (wc *WebConsole) setSession(w http.ResponseWriter, session *database.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   wc.config.Get().WebConsoleHTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})
}

// clearSession clears the session cookie
func (wc *WebConsole) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// requireAuth middleware ensures user is authenticated
func (wc *WebConsole) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := wc.getSession(r)
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// requireAdmin middleware ensures user has admin role
func (wc *WebConsole) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := wc.getSession(r)
		if session == nil || session.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// handleLogin handles login page and authentication
func (wc *WebConsole) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Check if already logged in
		if session := wc.getSession(r); session != nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		wc.renderLogin(w, r, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := wc.usersDB.ValidateCredentials(username, password)
	if err != nil || user == nil {
		wc.logger.LogError("Failed login attempt for user: %s", username)
		wc.renderLogin(w, r, "Invalid username or password")
		return
	}

	cfg := wc.config.Get()
	session, err := wc.usersDB.CreateSession(user.ID, cfg.WebConsoleSessionTimeout)
	if err != nil {
		wc.logger.LogError("Failed to create session: %v", err)
		wc.renderLogin(w, r, "Internal error")
		return
	}

	wc.setSession(w, session)
	wc.logger.LogInfo("User %s logged in", username)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleLogout handles logout
func (wc *WebConsole) handleLogout(w http.ResponseWriter, r *http.Request) {
	if session := wc.getSession(r); session != nil {
		wc.usersDB.DeleteSession(session.ID)
		wc.logger.LogInfo("User %s logged out", session.Username)
	}
	wc.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleDashboard handles the dashboard page
func (wc *WebConsole) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderDashboard(w, r, session)
}

// handleSettings handles the settings page
func (wc *WebConsole) handleSettings(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderSettings(w, r, session)
}

// handlePackages handles the packages page
func (wc *WebConsole) handlePackages(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderPackages(w, r, session)
}

// handlePackageUpload handles package upload
func (wc *WebConsole) handlePackageUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 500MB)
	if err := r.ParseMultipartForm(500 << 20); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("package")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	release := r.FormValue("release")
	component := r.FormValue("component")
	architecture := r.FormValue("architecture")

	if release == "" || component == "" || architecture == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "upload-*.deb")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temp file: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, file); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save file: %v", err), http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	if wc.pkgManager != nil {
		if pm, ok := wc.pkgManager.(interface {
			AddPackage(debPath, release, component, architecture string) error
		}); ok {
			if err := pm.AddPackage(tmpFile.Name(), release, component, architecture); err != nil {
				http.Error(w, fmt.Sprintf("Failed to add package: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s uploaded package %s", session.Username, header.Filename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Package uploaded successfully",
	})
}

// handleEvents handles the events page
func (wc *WebConsole) handleEvents(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderEvents(w, r, session)
}

// handleSearch handles the package search page
func (wc *WebConsole) handleSearch(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderSearch(w, r, session)
}

// handleLogs handles the daemon logs page
func (wc *WebConsole) handleLogs(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderLogs(w, r, session)
}

// handleUsers handles the users management page
func (wc *WebConsole) handleUsers(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderUsers(w, r, session)
}

// handleCVE handles the CVE dashboard page
func (wc *WebConsole) handleCVE(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderCVEDashboard(w, r, session)
}

// handleCVEFind handles the CVE find/search page
func (wc *WebConsole) handleCVEFind(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderCVEFind(w, r, session)
}

// handleSyncTrigger triggers a sync
func (wc *WebConsole) handleSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.syncer != nil {
		if s, ok := wc.syncer.(interface{ Sync() }); ok {
			go s.Sync()
		}
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s triggered sync", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Sync triggered",
	})
}

// API handlers

func (wc *WebConsole) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := map[string]interface{}{}

	// Use reflection to call GetStats regardless of concrete return type
	if wc.syncer != nil {
		v := reflect.ValueOf(wc.syncer)
		method := v.MethodByName("GetStats")
		if method.IsValid() {
			results := method.Call(nil)
			if len(results) > 0 {
				stats["sync"] = results[0].Interface()
			}
		}
	}
	if wc.httpServer != nil {
		v := reflect.ValueOf(wc.httpServer)
		method := v.MethodByName("GetStats")
		if method.IsValid() {
			results := method.Call(nil)
			if len(results) > 0 {
				stats["server"] = results[0].Interface()
			}
		}
	}

	// Get disk stats
	cfg := wc.config.Get()
	repoPath := cfg.RepositoryPath
	if repoPath != "" {
		diskStats := map[string]interface{}{}

		// Get filesystem stats
		var stat syscall.Statfs_t
		if err := syscall.Statfs(repoPath, &stat); err == nil {
			totalBytes := stat.Blocks * uint64(stat.Bsize)
			freeBytes := stat.Bfree * uint64(stat.Bsize)
			usedBytes := totalBytes - freeBytes
			diskStats["total_bytes"] = totalBytes
			diskStats["free_bytes"] = freeBytes
			diskStats["used_bytes"] = usedBytes
			// Use used bytes as approximate repository size (works when repo is on dedicated partition)
			diskStats["repository_size"] = usedBytes
		}

		stats["disk"] = diskStats
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (wc *WebConsole) handleAPISyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"running": false,
	}

	// Use reflection to call methods regardless of concrete return type
	if wc.syncer != nil {
		v := reflect.ValueOf(wc.syncer)

		// Call IsRunning
		isRunningMethod := v.MethodByName("IsRunning")
		if isRunningMethod.IsValid() {
			results := isRunningMethod.Call(nil)
			if len(results) > 0 {
				status["running"] = results[0].Interface()
			}
		}

		// Call GetStats
		getStatsMethod := v.MethodByName("GetStats")
		if getStatsMethod.IsValid() {
			results := getStatsMethod.Call(nil)
			if len(results) > 0 {
				status["stats"] = results[0].Interface()
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (wc *WebConsole) handleAPIRecentUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use reflection to call syncer.GetUpdatesDB()
	if wc.syncer == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"updates": []interface{}{},
		})
		return
	}

	v := reflect.ValueOf(wc.syncer)
	getUpdatesDBMethod := v.MethodByName("GetUpdatesDB")
	if !getUpdatesDBMethod.IsValid() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"updates": []interface{}{},
		})
		return
	}

	results := getUpdatesDBMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"updates": []interface{}{},
		})
		return
	}

	updatesDB := results[0]

	// Parse the limit parameter
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &limit); err == nil && parsed > 0 {
			if limit > 500 {
				limit = 500
			}
		}
	}

	// Call GetRecentUpdates on updatesDB
	getRecentMethod := updatesDB.MethodByName("GetRecentUpdates")
	if !getRecentMethod.IsValid() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"updates": []interface{}{},
		})
		return
	}

	recentResults := getRecentMethod.Call([]reflect.Value{reflect.ValueOf(limit)})
	if len(recentResults) < 2 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"updates": []interface{}{},
		})
		return
	}

	// Check for error (second return value)
	if !recentResults[1].IsNil() {
		http.Error(w, "Failed to get recent updates", http.StatusInternalServerError)
		return
	}

	updates := recentResults[0].Interface()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   recentResults[0].Len(),
		"updates": updates,
	})
}

func (wc *WebConsole) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := wc.usersDB.ListUsers()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list users: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
	})
}

func (wc *WebConsole) handleAPIUserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if params.Username == "" || params.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	if params.Role == "" {
		params.Role = "user"
	}

	if err := wc.usersDB.CreateUser(params.Username, params.Password, params.Email, params.Role); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s created user %s", session.Username, params.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "User created",
	})
}

func (wc *WebConsole) handleAPIUserUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		ID     int64  `json:"id"`
		Email  string `json:"email"`
		Role   string `json:"role"`
		Active bool   `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if err := wc.usersDB.UpdateUser(params.ID, params.Email, params.Role, params.Active); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update user: %v", err), http.StatusInternalServerError)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s updated user ID %d", session.Username, params.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "User updated",
	})
}

func (wc *WebConsole) handleAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		ID int64 `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Prevent deleting the last admin
	users, _ := wc.usersDB.ListUsers()
	adminCount := 0
	for _, u := range users {
		if u.Role == "admin" && u.Active {
			adminCount++
		}
	}

	user, _ := wc.usersDB.GetUser(params.ID)
	if user != nil && user.Role == "admin" && adminCount <= 1 {
		http.Error(w, "Cannot delete the last admin user", http.StatusBadRequest)
		return
	}

	if err := wc.usersDB.DeleteUser(params.ID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete user: %v", err), http.StatusInternalServerError)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s deleted user ID %d", session.Username, params.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "User deleted",
	})
}

func (wc *WebConsole) handleAPIUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		ID       int64  `json:"id"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if params.Password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	if err := wc.usersDB.UpdatePassword(params.ID, params.Password); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update password: %v", err), http.StatusInternalServerError)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s changed password for user ID %d", session.Username, params.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Password updated",
	})
}

func (wc *WebConsole) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := wc.config.Get()

	// Return config without sensitive data
	safeConfig := map[string]interface{}{
		"sync_interval":                   cfg.SyncInterval,
		"repository_path":                 cfg.RepositoryPath,
		"debian_mirror":                   cfg.DebianMirror,
		"debian_releases":                 cfg.DebianReleases,
		"debian_architectures":            cfg.DebianArchs,
		"debian_components":               cfg.DebianComponents,
		"http_enabled":                    cfg.HTTPEnabled,
		"http_port":                       cfg.HTTPPort,
		"https_enabled":                   cfg.HTTPSEnabled,
		"https_port":                      cfg.HTTPSPort,
		"tls_cert_file":                   cfg.TLSCertFile,
		"api_enabled":                     cfg.APIEnabled,
		"api_port":                        cfg.APIPort,
		"gpg_signing_enabled":             cfg.GPGSigningEnabled,
		"package_search_enabled":          cfg.PackageSearchEnabled,
		"max_disk_usage_percent":          cfg.MaxDiskUsagePercent,
		"max_concurrent_downloads":        cfg.MaxConcurrentDownloads,
		"web_console_https_enabled":       cfg.WebConsoleHTTPSEnabled,
		"web_console_tls_use_server_cert": cfg.WebConsoleTLSUseServerCert,
		"web_console_tls_cert_file":       cfg.WebConsoleTLSCertFile,
		"web_console_tls_key_file":        cfg.WebConsoleTLSKeyFile,
		"sync_artica_repository":          cfg.SyncArticaRepository,
		"artica_repository_ssl":           cfg.ArticaRepositorySSL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(safeConfig)
}

func (wc *WebConsole) handleAPIConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Update config
	wc.config.Update(func(cfg *config.Config) {
		if v, ok := params["sync_interval"].(float64); ok {
			cfg.SyncInterval = int(v)
		}
		if v, ok := params["max_disk_usage_percent"].(float64); ok {
			cfg.MaxDiskUsagePercent = int(v)
		}
		if v, ok := params["max_concurrent_downloads"].(float64); ok {
			cfg.MaxConcurrentDownloads = int(v)
		}
		// SSL settings for web console
		if v, ok := params["web_console_https_enabled"].(bool); ok {
			cfg.WebConsoleHTTPSEnabled = v
		}
		if v, ok := params["web_console_tls_use_server_cert"].(bool); ok {
			cfg.WebConsoleTLSUseServerCert = v
		}
		if v, ok := params["web_console_tls_cert_file"].(string); ok && v != "" {
			cfg.WebConsoleTLSCertFile = v
		}
		if v, ok := params["web_console_tls_key_file"].(string); ok && v != "" {
			cfg.WebConsoleTLSKeyFile = v
		}
		// Artica repository settings
		if v, ok := params["sync_artica_repository"].(bool); ok {
			cfg.SyncArticaRepository = v
		}
		if v, ok := params["artica_repository_ssl"].(bool); ok {
			cfg.ArticaRepositorySSL = v
		}
	})

	// Save config to file
	if err := wc.config.Save(wc.configPath); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s updated configuration", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Configuration updated",
	})
}

// GetUsersDB returns the users database
func (wc *WebConsole) GetUsersDB() *database.UsersDB {
	return wc.usersDB
}

// GetStaticPath returns the static assets URL path based on config directory name
func (wc *WebConsole) GetStaticPath() string {
	return "/" + wc.configDirName
}

// handleAPISearchPackage searches packages by name
func (wc *WebConsole) handleAPISearchPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"results": []interface{}{},
		})
		return
	}

	if wc.syncer == nil {
		http.Error(w, "Syncer not available", http.StatusServiceUnavailable)
		return
	}

	// Use reflection to get searchDB
	v := reflect.ValueOf(wc.syncer)
	getSearchDBMethod := v.MethodByName("GetSearchDB")
	if !getSearchDBMethod.IsValid() {
		http.Error(w, "Search not available", http.StatusServiceUnavailable)
		return
	}

	results := getSearchDBMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	searchDB := results[0]
	release := r.URL.Query().Get("release")
	limit := 100

	// Call SearchByName
	searchMethod := searchDB.MethodByName("SearchByName")
	if !searchMethod.IsValid() {
		http.Error(w, "Search method not available", http.StatusServiceUnavailable)
		return
	}

	searchResults := searchMethod.Call([]reflect.Value{
		reflect.ValueOf(query),
		reflect.ValueOf(release),
		reflect.ValueOf(limit),
	})

	if len(searchResults) < 2 || !searchResults[1].IsNil() {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"count":   searchResults[0].Len(),
		"results": searchResults[0].Interface(),
	})
}

// handleAPISearchFile searches for packages containing a file
func (wc *WebConsole) handleAPISearchFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   0,
			"results": []interface{}{},
		})
		return
	}

	if wc.syncer == nil {
		http.Error(w, "Syncer not available", http.StatusServiceUnavailable)
		return
	}

	v := reflect.ValueOf(wc.syncer)
	getSearchDBMethod := v.MethodByName("GetSearchDB")
	if !getSearchDBMethod.IsValid() {
		http.Error(w, "Search not available", http.StatusServiceUnavailable)
		return
	}

	results := getSearchDBMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	searchDB := results[0]
	release := r.URL.Query().Get("release")
	arch := r.URL.Query().Get("arch")
	limit := 100

	searchMethod := searchDB.MethodByName("SearchByFile")
	if !searchMethod.IsValid() {
		http.Error(w, "Search method not available", http.StatusServiceUnavailable)
		return
	}

	searchResults := searchMethod.Call([]reflect.Value{
		reflect.ValueOf(path),
		reflect.ValueOf(release),
		reflect.ValueOf(arch),
		reflect.ValueOf(limit),
	})

	if len(searchResults) < 2 || !searchResults[1].IsNil() {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":    path,
		"count":   searchResults[0].Len(),
		"results": searchResults[0].Interface(),
	})
}

// handleAPIPackageFiles lists files in a package
func (wc *WebConsole) handleAPIPackageFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pkg := r.URL.Query().Get("package")
	if pkg == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 0,
			"files": []interface{}{},
		})
		return
	}

	if wc.syncer == nil {
		http.Error(w, "Syncer not available", http.StatusServiceUnavailable)
		return
	}

	v := reflect.ValueOf(wc.syncer)
	getSearchDBMethod := v.MethodByName("GetSearchDB")
	if !getSearchDBMethod.IsValid() {
		http.Error(w, "Search not available", http.StatusServiceUnavailable)
		return
	}

	results := getSearchDBMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	searchDB := results[0]
	release := r.URL.Query().Get("release")
	arch := r.URL.Query().Get("arch")

	searchMethod := searchDB.MethodByName("GetPackageFiles")
	if !searchMethod.IsValid() {
		http.Error(w, "Method not available", http.StatusServiceUnavailable)
		return
	}

	searchResults := searchMethod.Call([]reflect.Value{
		reflect.ValueOf(pkg),
		reflect.ValueOf(release),
		reflect.ValueOf(arch),
	})

	if len(searchResults) < 2 || !searchResults[1].IsNil() {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"package": pkg,
		"count":   searchResults[0].Len(),
		"files":   searchResults[0].Interface(),
	})
}

// handleAPILogs returns daemon log entries
func (wc *WebConsole) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get log file path from config
	cfg := wc.config.Get()
	logPath := cfg.LogPath
	if logPath == "" {
		logPath = filepath.Join(filepath.Dir(wc.configPath), "sync.log")
	}

	// Read last N lines from log file
	lines := 200
	if l := r.URL.Query().Get("lines"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &lines); err == nil && parsed > 0 {
			if lines > 1000 {
				lines = 1000
			}
		}
	}

	// Read log file
	file, err := os.Open(logPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Cannot open log file: %v", err),
			"logs":  []string{},
		})
		return
	}
	defer file.Close()

	// Get file size and read last portion
	stat, err := file.Stat()
	if err != nil {
		http.Error(w, "Cannot stat log file", http.StatusInternalServerError)
		return
	}

	// Read approximately last 100KB or less
	readSize := int64(100 * 1024)
	if stat.Size() < readSize {
		readSize = stat.Size()
	}

	offset := stat.Size() - readSize
	if offset < 0 {
		offset = 0
	}

	_, err = file.Seek(offset, 0)
	if err != nil {
		http.Error(w, "Cannot seek log file", http.StatusInternalServerError)
		return
	}

	data := make([]byte, readSize)
	n, err := file.Read(data)
	if err != nil && err != io.EOF {
		http.Error(w, "Cannot read log file", http.StatusInternalServerError)
		return
	}

	// Split into lines and get last N
	content := string(data[:n])
	allLines := splitLines(content)

	// Skip first partial line if we started mid-file
	if offset > 0 && len(allLines) > 0 {
		allLines = allLines[1:]
	}

	// Get last N lines
	if len(allLines) > lines {
		allLines = allLines[len(allLines)-lines:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(allLines),
		"logs":  allLines,
	})
}

// splitLines splits a string into lines
func splitLines(s string) []string {
	var lines []string
	var current string
	for _, c := range s {
		if c == '\n' {
			if current != "" {
				lines = append(lines, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// CVE API handlers

// handleAPICVEStatus returns CVE scanner status
func (wc *WebConsole) handleAPICVEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":     false,
			"initialized": false,
			"error":       "CVE scanner not available",
		})
		return
	}

	status := wc.cveScanner.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleAPICVEUpdate triggers CVE database update
func (wc *WebConsole) handleAPICVEUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s triggered CVE database update", session.Username)

	if err := wc.cveScanner.UpdateCVEData(); err != nil {
		wc.logger.LogError("CVE database update failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "CVE database updated successfully",
	})
}

// handleAPICVEScan triggers a CVE scan
func (wc *WebConsole) handleAPICVEScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s triggered CVE scan", session.Username)

	release := r.URL.Query().Get("release")
	component := r.URL.Query().Get("component")
	arch := r.URL.Query().Get("architecture")

	result, err := wc.cveScanner.Scan(release, component, arch, false)
	if err != nil {
		wc.logger.LogError("CVE scan failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"result": result,
	})
}

// handleAPICVEVulnerable returns list of vulnerable packages
func (wc *WebConsole) handleAPICVEVulnerable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	release := r.URL.Query().Get("release")
	component := r.URL.Query().Get("component")
	arch := r.URL.Query().Get("architecture")

	result, err := wc.cveScanner.Scan(release, component, arch, true)
	if err != nil {
		http.Error(w, "CVE scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPICVEPackage returns CVE info for a specific package
func (wc *WebConsole) handleAPICVEPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	packageName := r.URL.Query().Get("name")
	if packageName == "" {
		packageName = r.URL.Query().Get("package")
	}
	if packageName == "" {
		http.Error(w, "Missing required parameter: name or package", http.StatusBadRequest)
		return
	}

	release := r.URL.Query().Get("release")

	result, err := wc.cveScanner.GetPackageCVEs(packageName, release)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPICVESearch searches for a specific CVE
func (wc *WebConsole) handleAPICVESearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.cveScanner == nil {
		http.Error(w, "CVE scanner not available", http.StatusServiceUnavailable)
		return
	}

	cveID := r.URL.Query().Get("cve")
	if cveID == "" {
		cveID = r.URL.Query().Get("id")
	}
	if cveID == "" {
		http.Error(w, "Missing required parameter: cve or id", http.StatusBadRequest)
		return
	}

	result, err := wc.cveScanner.SearchCVE(cveID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
