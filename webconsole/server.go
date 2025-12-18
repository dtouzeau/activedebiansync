package webconsole

import (
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/gpg"
	"activedebiansync/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	ForceSync() error
	IsRunning() bool
	StopSync() bool
	IsStopping() bool
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

// ReplicationManagerProvider interface for cluster replication
type ReplicationManagerProvider interface {
	GetStatus() interface{}
	ReplicateToPeers() error
	ManualReplicate(peerName string) error
	PullFromPeer(peerName string) error
	StopReplication() error
	IsStopping() bool
	IsRunning() bool
}

// WebConsole manages the web console server
type WebConsole struct {
	config         *config.Config
	configPath     string
	configDirName  string
	logger         *utils.Logger
	usersDB        *database.UsersDB
	eventsDB       *database.EventsDB
	securityDB     *database.SecurityDB
	clientsDB      *database.ClientsDB
	clusterDB      *database.ClusterDB
	server         *http.Server
	httpServer     interface{}
	syncer         interface{}
	pkgManager     interface{}
	cveScanner     CVEScannerProvider
	replicationMgr ReplicationManagerProvider
	oauthHandler   *ConsoleOAuthHandler
	templates      *template.Template
	sessionSecret  string
	basePath       string
	trustedProxies []string
	version        string
	mu             sync.RWMutex
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
func NewWebConsole(cfg *config.Config, configPath string, logger *utils.Logger, version string) (*WebConsole, error) {
	cfgData := cfg.Get()

	// Initialize users database
	dbPath := cfg.GetDatabasePath()
	usersDB, err := database.NewUsersDB(dbPath)
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

	// Parse trusted proxies
	var trustedProxies []string
	if cfgData.WebConsoleTrustedProxies != "" {
		for _, p := range strings.Split(cfgData.WebConsoleTrustedProxies, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				trustedProxies = append(trustedProxies, p)
			}
		}
	}

	// Normalize base path
	basePath := strings.TrimSuffix(cfgData.WebConsoleBasePath, "/")
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	wc := &WebConsole{
		config:         cfg,
		configPath:     configPath,
		configDirName:  filepath.Base(filepath.Dir(configPath)),
		logger:         logger,
		usersDB:        usersDB,
		sessionSecret:  sessionSecret,
		basePath:       basePath,
		trustedProxies: trustedProxies,
		version:        version,
	}

	// Initialize OAuth handler
	wc.oauthHandler = NewConsoleOAuthHandler(cfg, logger)

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

// SetEventsDB sets the events database for tracking sync events
func (wc *WebConsole) SetEventsDB(db *database.EventsDB) {
	wc.eventsDB = db
}

// GetEventsDB returns the events database
func (wc *WebConsole) GetEventsDB() *database.EventsDB {
	return wc.eventsDB
}

// SetSecurityDB sets the security database for access control rules
func (wc *WebConsole) SetSecurityDB(db *database.SecurityDB) {
	wc.securityDB = db
}

// GetSecurityDB returns the security database
func (wc *WebConsole) GetSecurityDB() *database.SecurityDB {
	return wc.securityDB
}

// SetClientsDB sets the clients database for tracking client statistics
func (wc *WebConsole) SetClientsDB(db *database.ClientsDB) {
	wc.clientsDB = db
}

// GetClientsDB returns the clients database
func (wc *WebConsole) GetClientsDB() *database.ClientsDB {
	return wc.clientsDB
}

// SetClusterDB sets the cluster database for replication statistics
func (wc *WebConsole) SetClusterDB(db *database.ClusterDB) {
	wc.clusterDB = db
}

// SetReplicationManager sets the replication manager
func (wc *WebConsole) SetReplicationManager(rm ReplicationManagerProvider) {
	wc.replicationMgr = rm
}

// isTrustedProxy checks if the given IP is a trusted proxy
func (wc *WebConsole) isTrustedProxy(ip string) bool {
	// Always trust localhost
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	// Check against configured trusted proxies
	for _, trusted := range wc.trustedProxies {
		if strings.Contains(trusted, "/") {
			// CIDR notation
			_, cidr, err := net.ParseCIDR(trusted)
			if err == nil {
				testIP := net.ParseIP(ip)
				if testIP != nil && cidr.Contains(testIP) {
					return true
				}
			}
		} else {
			// Single IP
			if trusted == ip {
				return true
			}
		}
	}
	return false
}

// getClientIP extracts the real client IP from request, respecting X-Forwarded-For if from trusted proxy
func (wc *WebConsole) getClientIP(r *http.Request) string {
	// Get the remote address
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}

	// Only trust X-Forwarded-For from trusted proxies
	if wc.isTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteIP
}

// reverseProxyMiddleware handles reverse proxy headers and base path stripping
func (wc *WebConsole) reverseProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get remote IP for logging
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP == "" {
			remoteIP = r.RemoteAddr
		}

		// Handle X-Forwarded-Proto for secure detection
		if wc.isTrustedProxy(remoteIP) {
			if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
				if proto == "https" {
					r.URL.Scheme = "https"
				}
			}
		}

		// Strip base path if configured
		if wc.basePath != "" && strings.HasPrefix(r.URL.Path, wc.basePath) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, wc.basePath)
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}

		next.ServeHTTP(w, r)
	})
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

	// Use external assets if found, otherwise use embedded assets
	var fileServer http.Handler
	if _, err := os.Stat(staticPath); err == nil {
		// Use external assets directory
		fileServer = http.FileServer(http.Dir(staticPath))
		wc.logger.LogInfo("Using external assets from: %s", staticPath)
	} else if HasEmbeddedAssets() {
		// Use embedded assets
		embeddedFS, err := GetEmbeddedAssetsFS()
		if err != nil {
			wc.logger.LogError("Failed to load embedded assets: %v", err)
		} else {
			fileServer = http.FileServer(embeddedFS)
			wc.logger.LogInfo("Using embedded assets (no external assets found)")
		}
	}

	if fileServer != nil {
		// Use config directory name as the root path (e.g., /ActiveDebianSync/*)
		mux.Handle("/"+configDirName+"/", http.StripPrefix("/"+configDirName+"/", fileServer))
		// Also keep /static/ for backwards compatibility
		mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	}

	// Public routes
	mux.HandleFunc("/login", wc.handleLogin)
	mux.HandleFunc("/logout", wc.handleLogout)
	mux.HandleFunc("/oauth/login", wc.handleOAuthLogin)
	mux.HandleFunc("/oauth/callback", wc.handleOAuthCallback)

	// Protected routes
	mux.HandleFunc("/", wc.requireAuth(wc.handleDashboard))
	mux.HandleFunc("/dashboard", wc.requireAuth(wc.handleDashboard))
	mux.HandleFunc("/repositories-status", wc.requireAuth(wc.handleRepositoriesStatus))
	mux.HandleFunc("/settings", wc.requireAuth(wc.handleSettings))
	mux.HandleFunc("/packages", wc.requireAuth(wc.handlePackages))
	mux.HandleFunc("/packages/upload", wc.requireAuth(wc.handlePackageUpload))
	mux.HandleFunc("/events", wc.requireAuth(wc.handleEvents))
	mux.HandleFunc("/search", wc.requireAuth(wc.handleSearch))
	mux.HandleFunc("/logs", wc.requireAuth(wc.handleLogs))
	mux.HandleFunc("/users", wc.requireAuth(wc.requireAdmin(wc.handleUsers)))
	mux.HandleFunc("/security", wc.requireAuth(wc.requireAdmin(wc.handleSecurity)))
	mux.HandleFunc("/clients", wc.requireAuth(wc.handleClients))
	mux.HandleFunc("/cve", wc.requireAuth(wc.handleCVE))
	mux.HandleFunc("/cve/find", wc.requireAuth(wc.handleCVEFind))
	mux.HandleFunc("/sync/trigger", wc.requireAuth(wc.handleSyncTrigger))
	mux.HandleFunc("/sync/stop", wc.requireAuth(wc.handleSyncStop))

	// API routes for web console
	mux.HandleFunc("/api/console/stats", wc.requireAuth(wc.handleAPIStats))
	mux.HandleFunc("/api/console/sync/status", wc.requireAuth(wc.handleAPISyncStatus))
	mux.HandleFunc("/api/console/sync/activity", wc.requireAuth(wc.handleAPISyncActivity))
	mux.HandleFunc("/api/console/sync/failed-files", wc.requireAuth(wc.handleAPIFailedFiles))
	mux.HandleFunc("/api/console/users", wc.requireAuth(wc.requireAdmin(wc.handleAPIUsers)))
	mux.HandleFunc("/api/console/users/create", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserCreate)))
	mux.HandleFunc("/api/console/users/update", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserUpdate)))
	mux.HandleFunc("/api/console/users/delete", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserDelete)))
	mux.HandleFunc("/api/console/users/password", wc.requireAuth(wc.requireAdmin(wc.handleAPIUserPassword)))
	mux.HandleFunc("/api/console/config", wc.requireAuth(wc.requireAdmin(wc.handleAPIConfig)))
	mux.HandleFunc("/api/console/config/update", wc.requireAuth(wc.requireAdmin(wc.handleAPIConfigUpdate)))
	mux.HandleFunc("/api/updates/packages/recent", wc.requireAuth(wc.handleAPIRecentUpdates))
	mux.HandleFunc("/api/console/events", wc.requireAuth(wc.handleAPISyncEvents))
	mux.HandleFunc("/api/console/events/stats", wc.requireAuth(wc.handleAPIEventsStats))
	mux.HandleFunc("/api/console/events/daily", wc.requireAuth(wc.handleAPIEventsDailySummary))
	mux.HandleFunc("/api/search/package", wc.requireAuth(wc.handleAPISearchPackage))
	mux.HandleFunc("/api/search/file", wc.requireAuth(wc.handleAPISearchFile))
	mux.HandleFunc("/api/search/package-files", wc.requireAuth(wc.handleAPIPackageFiles))
	mux.HandleFunc("/api/logs", wc.requireAuth(wc.handleAPILogs))
	mux.HandleFunc("/api/console/repository/sizes", wc.requireAuth(wc.handleAPIRepositorySizes))
	mux.HandleFunc("/api/console/repository/scan", wc.requireAuth(wc.handleAPIRepositoryScan))

	// CVE API routes
	mux.HandleFunc("/api/console/cve/status", wc.requireAuth(wc.handleAPICVEStatus))
	mux.HandleFunc("/api/console/cve/update", wc.requireAuth(wc.handleAPICVEUpdate))
	mux.HandleFunc("/api/console/cve/scan", wc.requireAuth(wc.handleAPICVEScan))
	mux.HandleFunc("/api/console/cve/vulnerable", wc.requireAuth(wc.handleAPICVEVulnerable))
	mux.HandleFunc("/api/console/cve/package", wc.requireAuth(wc.handleAPICVEPackage))
	mux.HandleFunc("/api/console/cve/search", wc.requireAuth(wc.handleAPICVESearch))

	// Security rules API (admin only)
	mux.HandleFunc("/api/console/security/rules", wc.requireAuth(wc.requireAdmin(wc.handleAPISecurityRules)))
	mux.HandleFunc("/api/console/security/rules/create", wc.requireAuth(wc.requireAdmin(wc.handleAPISecurityRuleCreate)))
	mux.HandleFunc("/api/console/security/rules/update", wc.requireAuth(wc.requireAdmin(wc.handleAPISecurityRuleUpdate)))
	mux.HandleFunc("/api/console/security/rules/delete", wc.requireAuth(wc.requireAdmin(wc.handleAPISecurityRuleDelete)))
	mux.HandleFunc("/api/console/security/stats", wc.requireAuth(wc.handleAPISecurityStats))
	mux.HandleFunc("/api/console/security/reload", wc.requireAuth(wc.requireAdmin(wc.handleAPISecurityReload)))

	// Clients statistics API
	mux.HandleFunc("/api/console/clients/stats", wc.requireAuth(wc.handleAPIClientsStats))
	mux.HandleFunc("/api/console/clients/top", wc.requireAuth(wc.handleAPIClientsTop))
	mux.HandleFunc("/api/console/clients/daily", wc.requireAuth(wc.handleAPIClientsDaily))
	mux.HandleFunc("/api/console/clients/records", wc.requireAuth(wc.handleAPIClientsRecords))
	mux.HandleFunc("/api/console/clients/history", wc.requireAuth(wc.handleAPIClientHistory))
	mux.HandleFunc("/api/console/clients/cleanup", wc.requireAuth(wc.requireAdmin(wc.handleAPIClientsCleanup)))

	// GPG API
	mux.HandleFunc("/api/console/gpg/status", wc.requireAuth(wc.handleAPIGPGStatus))
	mux.HandleFunc("/api/console/gpg/generate", wc.requireAuth(wc.requireAdmin(wc.handleAPIGPGGenerate)))

	// Cluster replication pages
	mux.HandleFunc("/cluster", wc.requireAuth(wc.handleCluster))
	mux.HandleFunc("/cluster/events", wc.requireAuth(wc.handleClusterEvents))

	// Cluster replication API
	mux.HandleFunc("/api/console/cluster/status", wc.requireAuth(wc.handleAPIClusterStatus))
	mux.HandleFunc("/api/console/cluster/stats", wc.requireAuth(wc.handleAPIClusterStats))
	mux.HandleFunc("/api/console/cluster/nodes", wc.requireAuth(wc.handleAPIClusterNodes))
	mux.HandleFunc("/api/console/cluster/nodes/add", wc.requireAuth(wc.requireAdmin(wc.handleAPIClusterNodeAdd)))
	mux.HandleFunc("/api/console/cluster/nodes/remove", wc.requireAuth(wc.requireAdmin(wc.handleAPIClusterNodeRemove)))
	mux.HandleFunc("/api/console/cluster/replicate", wc.requireAuth(wc.handleAPIClusterReplicate))
	mux.HandleFunc("/api/console/cluster/stop", wc.requireAuth(wc.handleAPIClusterStopReplication))
	mux.HandleFunc("/api/console/cluster/history", wc.requireAuth(wc.handleAPIClusterHistory))
	mux.HandleFunc("/api/console/cluster/oauth", wc.requireAuth(wc.requireAdmin(wc.handleAPIClusterOAuth)))
	mux.HandleFunc("/api/console/cluster/toggle", wc.requireAuth(wc.requireAdmin(wc.handleAPIClusterToggle)))
	mux.HandleFunc("/api/console/cluster/settings", wc.requireAuth(wc.requireAdmin(wc.handleAPIClusterSettings)))

	addr := fmt.Sprintf("%s:%d", cfg.WebConsoleListenAddr, cfg.WebConsolePort)

	// Wrap mux with reverse proxy middleware
	var handler http.Handler = mux
	handler = wc.reverseProxyMiddleware(handler)

	wc.server = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Start session cleanup goroutine
	go wc.cleanupSessions(ctx)

	// Start directory size scanner
	wc.startDirSizeScanner()

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
	cfg := wc.config.Get()
	// Use secure cookies if HTTPS enabled or if explicitly set for reverse proxy
	secureCookie := cfg.WebConsoleHTTPSEnabled || cfg.WebConsoleSecureCookies

	// Cookie path should include base path if set
	cookiePath := "/"
	if wc.basePath != "" {
		cookiePath = wc.basePath + "/"
	}

	// Use Lax SameSite when behind reverse proxy to allow navigation
	sameSite := http.SameSiteStrictMode
	if wc.basePath != "" || len(wc.trustedProxies) > 0 {
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: sameSite,
		Expires:  session.ExpiresAt,
	})
}

// clearSession clears the session cookie
func (wc *WebConsole) clearSession(w http.ResponseWriter) {
	cookiePath := "/"
	if wc.basePath != "" {
		cookiePath = wc.basePath + "/"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     cookiePath,
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// requireAuth middleware ensures user is authenticated
func (wc *WebConsole) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := wc.getSession(r)
		if session == nil {
			// Return JSON error for API endpoints
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   "Unauthorized",
					"message": "Session expired. Please login again.",
				})
				return
			}
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

		// If OAuth is enabled and local login is disabled, redirect to OAuth
		if wc.oauthHandler.IsEnabled() && !wc.oauthHandler.AllowsLocalLogin() {
			http.Redirect(w, r, "/oauth/login", http.StatusFound)
			return
		}

		wc.renderLogin(w, r, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if local login is allowed
	if wc.oauthHandler.IsEnabled() && !wc.oauthHandler.AllowsLocalLogin() {
		wc.renderLogin(w, r, "Local login is disabled. Please use OAuth.")
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

// handleOAuthLogin initiates OAuth login flow
func (wc *WebConsole) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !wc.oauthHandler.IsEnabled() {
		http.Error(w, "OAuth is not enabled", http.StatusBadRequest)
		return
	}

	// Get return URL from query parameter
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		returnURL = "/dashboard"
	}

	authURL, err := wc.oauthHandler.GetAuthorizationURL(returnURL)
	if err != nil {
		wc.logger.LogError("Failed to get OAuth authorization URL: %v", err)
		http.Error(w, "Failed to initiate OAuth login", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback handles the OAuth callback
func (wc *WebConsole) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !wc.oauthHandler.IsEnabled() {
		http.Error(w, "OAuth is not enabled", http.StatusBadRequest)
		return
	}

	// Check for error from OAuth provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		wc.logger.LogError("OAuth error: %s - %s", errParam, errDesc)
		wc.renderLogin(w, r, fmt.Sprintf("OAuth error: %s", errDesc))
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		wc.renderLogin(w, r, "Invalid OAuth callback")
		return
	}

	result, err := wc.oauthHandler.HandleCallback(code, state)
	if err != nil {
		wc.logger.LogError("OAuth callback failed: %v", err)
		wc.renderLogin(w, r, "OAuth authentication failed")
		return
	}

	// Create session for the OAuth user
	cfg := wc.config.Get()
	session, err := wc.usersDB.CreateOAuthSession(result.Username, result.IsAdmin, result.AccessToken, cfg.WebConsoleSessionTimeout)
	if err != nil {
		wc.logger.LogError("Failed to create OAuth session: %v", err)
		wc.renderLogin(w, r, "Failed to create session")
		return
	}

	wc.setSession(w, session)
	wc.logger.LogInfo("OAuth user %s logged in (admin: %v)", result.Username, result.IsAdmin)

	// Redirect to return URL or dashboard
	returnURL := result.ReturnURL
	if returnURL == "" {
		returnURL = "/dashboard"
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
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

// handleSecurity handles the security rules management page
func (wc *WebConsole) handleSecurity(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderSecurity(w, r, session)
}

// handleClients handles the clients statistics page
func (wc *WebConsole) handleClients(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderClients(w, r, session)
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

// handleSyncTrigger triggers a forced sync (bypassing time restrictions)
func (wc *WebConsole) handleSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := wc.getSession(r)

	// Check if sync is already running
	if wc.syncer != nil {
		v := reflect.ValueOf(wc.syncer)
		isRunningMethod := v.MethodByName("IsRunning")
		if isRunningMethod.IsValid() {
			results := isRunningMethod.Call(nil)
			if len(results) > 0 && results[0].Bool() {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "running",
					"message": "Sync is already in progress",
				})
				return
			}
		}
	}

	if wc.syncer != nil {
		// Use ForceSync to bypass time restrictions
		if s, ok := wc.syncer.(interface{ ForceSync() error }); ok {
			go func() {
				if err := s.ForceSync(); err != nil {
					wc.logger.LogError("Forced sync failed: %v", err)
				}
			}()
		}
	}

	wc.logger.LogInfo("User %s triggered forced sync", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Sync started (time restrictions bypassed)",
	})
}

// handleSyncStop requests to stop the current sync operation
func (wc *WebConsole) handleSyncStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := wc.getSession(r)
	w.Header().Set("Content-Type", "application/json")

	if wc.syncer == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Syncer not available",
		})
		return
	}

	// Check if sync is running using reflection
	v := reflect.ValueOf(wc.syncer)
	isRunningMethod := v.MethodByName("IsRunning")
	if isRunningMethod.IsValid() {
		results := isRunningMethod.Call(nil)
		if len(results) > 0 && !results[0].Bool() {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "not_running",
				"message": "No synchronization is currently running",
			})
			return
		}
	}

	// Call StopSync using reflection
	stopMethod := v.MethodByName("StopSync")
	if stopMethod.IsValid() {
		results := stopMethod.Call(nil)
		if len(results) > 0 && results[0].Bool() {
			wc.logger.LogInfo("User %s requested sync stop", session.Username)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "stopping",
				"message": "Synchronization stop requested - will stop after current operation",
			})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "error",
		"message": "Failed to request sync stop",
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
		"running":  false,
		"stopping": false,
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

		// Call IsStopping
		isStoppingMethod := v.MethodByName("IsStopping")
		if isStoppingMethod.IsValid() {
			results := isStoppingMethod.Call(nil)
			if len(results) > 0 {
				status["stopping"] = results[0].Interface()
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

func (wc *WebConsole) handleAPIFailedFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	failedFiles := []interface{}{}

	if wc.syncer != nil {
		v := reflect.ValueOf(wc.syncer)
		getFailedFilesMethod := v.MethodByName("GetFailedFiles")
		if getFailedFilesMethod.IsValid() {
			results := getFailedFilesMethod.Call(nil)
			if len(results) > 0 && !results[0].IsNil() {
				failedFiles = make([]interface{}, results[0].Len())
				for i := 0; i < results[0].Len(); i++ {
					failedFiles[i] = results[0].Index(i).Interface()
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":        len(failedFiles),
		"failed_files": failedFiles,
	})
}

func (wc *WebConsole) handleAPISyncActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if wc.syncer == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	v := reflect.ValueOf(wc.syncer)
	getActivityMethod := v.MethodByName("GetActivity")
	if !getActivityMethod.IsValid() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	results := getActivityMethod.Call(nil)
	if len(results) == 0 || results[0].IsNil() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	activity := results[0].Interface()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active":   true,
		"activity": activity,
	})
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
		"sync_allowed_hours_enabled":      cfg.SyncAllowedHoursEnabled,
		"sync_allowed_hours_start":        cfg.SyncAllowedHoursStart,
		"sync_allowed_hours_end":          cfg.SyncAllowedHoursEnd,
		"http_enabled":                    cfg.HTTPEnabled,
		"http_port":                       cfg.HTTPPort,
		"https_enabled":                   cfg.HTTPSEnabled,
		"https_port":                      cfg.HTTPSPort,
		"tls_cert_file":                   cfg.TLSCertFile,
		"api_enabled":                     cfg.APIEnabled,
		"api_port":                        cfg.APIPort,
		"gpg_signing_enabled":             cfg.GPGSigningEnabled,
		"gpg_private_key_path":            cfg.GPGPrivateKeyPath,
		"gpg_public_key_path":             cfg.GPGPublicKeyPath,
		"gpg_key_name":                    cfg.GPGKeyName,
		"gpg_key_email":                   cfg.GPGKeyEmail,
		"gpg_key_comment":                 cfg.GPGKeyComment,
		"package_search_enabled":          cfg.PackageSearchEnabled,
		"max_disk_usage_percent":          cfg.MaxDiskUsagePercent,
		"max_concurrent_downloads":        cfg.MaxConcurrentDownloads,
		"web_console_https_enabled":       cfg.WebConsoleHTTPSEnabled,
		"web_console_tls_use_server_cert": cfg.WebConsoleTLSUseServerCert,
		"web_console_tls_cert_file":       cfg.WebConsoleTLSCertFile,
		"web_console_tls_key_file":        cfg.WebConsoleTLSKeyFile,
		"sync_artica_repository":          cfg.SyncArticaRepository,
		"artica_repository_ssl":           cfg.ArticaRepositorySSL,
		"sync_translations":               cfg.SyncTranslations,
		"translation_languages":           cfg.TranslationLanguages,
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
		// Sync time restriction settings
		if v, ok := params["sync_allowed_hours_enabled"].(bool); ok {
			cfg.SyncAllowedHoursEnabled = v
		}
		if v, ok := params["sync_allowed_hours_start"].(string); ok && v != "" {
			cfg.SyncAllowedHoursStart = v
		}
		if v, ok := params["sync_allowed_hours_end"].(string); ok && v != "" {
			cfg.SyncAllowedHoursEnd = v
		}
		// Debian releases
		if v, ok := params["debian_releases"].([]interface{}); ok {
			releases := make([]string, 0, len(v))
			for _, r := range v {
				if rs, ok := r.(string); ok && rs != "" {
					releases = append(releases, rs)
				}
			}
			if len(releases) > 0 {
				cfg.DebianReleases = releases
			}
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
		// Translation settings
		if v, ok := params["sync_translations"].(bool); ok {
			cfg.SyncTranslations = v
		}
		if v, ok := params["translation_languages"].([]interface{}); ok {
			langs := make([]string, 0, len(v))
			for _, l := range v {
				if ls, ok := l.(string); ok && ls != "" {
					langs = append(langs, ls)
				}
			}
			cfg.TranslationLanguages = langs
		}
		// GPG settings
		if v, ok := params["gpg_signing_enabled"].(bool); ok {
			cfg.GPGSigningEnabled = v
		}
		if v, ok := params["gpg_key_name"].(string); ok {
			cfg.GPGKeyName = v
		}
		if v, ok := params["gpg_key_email"].(string); ok {
			cfg.GPGKeyEmail = v
		}
		if v, ok := params["gpg_key_comment"].(string); ok {
			cfg.GPGKeyComment = v
		}
		if v, ok := params["gpg_private_key_path"].(string); ok && v != "" {
			cfg.GPGPrivateKeyPath = v
		}
		if v, ok := params["gpg_public_key_path"].(string); ok && v != "" {
			cfg.GPGPublicKeyPath = v
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

// handleAPISyncEvents returns recent sync events from the events database
func (wc *WebConsole) handleAPISyncEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.eventsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":  0,
			"events": []interface{}{},
			"error":  "Events database not initialized",
		})
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := parseInt(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	repository := r.URL.Query().Get("repository")

	var events []database.SyncEvent
	var err error

	if repository != "" {
		events, err = wc.eventsDB.GetEventsByRepository(repository, limit)
	} else {
		events, err = wc.eventsDB.GetRecentEvents(limit)
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":  0,
			"events": []interface{}{},
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(events),
		"events": events,
	})
}

// handleAPIEventsStats returns aggregated statistics per repository
func (wc *WebConsole) handleAPIEventsStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.eventsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stats": []interface{}{},
			"error": "Events database not initialized",
		})
		return
	}

	stats, err := wc.eventsDB.GetStatsByRepository()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stats": []interface{}{},
			"error": err.Error(),
		})
		return
	}

	totalCount, _ := wc.eventsDB.GetTotalEventCount()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats":       stats,
		"total_count": totalCount,
	})
}

// handleAPIEventsDailySummary returns daily summary of sync events
func (wc *WebConsole) handleAPIEventsDailySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.eventsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"summary": []interface{}{},
			"error":   "Events database not initialized",
		})
		return
	}

	// Parse days parameter
	daysStr := r.URL.Query().Get("days")
	days := 15
	if daysStr != "" {
		if d, err := parseInt(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	summary, err := wc.eventsDB.GetDailySummary(days)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"summary": []interface{}{},
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"summary": summary,
		"days":    days,
	})
}

// parseInt is a helper function to parse integer from string
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// handleAPISecurityRules returns all security rules
func (wc *WebConsole) handleAPISecurityRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rules": []interface{}{},
			"error": "Security database not initialized",
		})
		return
	}

	rules, err := wc.securityDB.GetAllRules()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rules": []interface{}{},
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

// handleAPISecurityRuleCreate creates a new security rule
func (wc *WebConsole) handleAPISecurityRuleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Security database not initialized",
		})
		return
	}

	var rule database.SecurityRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Invalid JSON: " + err.Error(),
		})
		return
	}

	if err := wc.securityDB.CreateRule(&rule); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	wc.logger.LogInfo("Security rule created: %s (type: %s)", rule.Name, rule.Type)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"rule":   rule,
	})
}

// handleAPISecurityRuleUpdate updates an existing security rule
func (wc *WebConsole) handleAPISecurityRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Security database not initialized",
		})
		return
	}

	var rule database.SecurityRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Invalid JSON: " + err.Error(),
		})
		return
	}

	if rule.ID == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Rule ID is required",
		})
		return
	}

	if err := wc.securityDB.UpdateRule(&rule); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	wc.logger.LogInfo("Security rule updated: %s (ID: %d)", rule.Name, rule.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"rule":   rule,
	})
}

// handleAPISecurityRuleDelete deletes a security rule
func (wc *WebConsole) handleAPISecurityRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Security database not initialized",
		})
		return
	}

	// Get ID from query param or body
	var ruleID int64
	idStr := r.URL.Query().Get("id")
	if idStr != "" {
		id, err := parseInt(idStr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  "Invalid rule ID",
			})
			return
		}
		ruleID = int64(id)
	} else {
		var body struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			ruleID = body.ID
		}
	}

	if ruleID == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Rule ID is required",
		})
		return
	}

	if err := wc.securityDB.DeleteRule(ruleID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	wc.logger.LogInfo("Security rule deleted: ID %d", ruleID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
	})
}

// handleAPISecurityStats returns security statistics
func (wc *WebConsole) handleAPISecurityStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stats": map[string]interface{}{},
			"error": "Security database not initialized",
		})
		return
	}

	stats, err := wc.securityDB.GetStats()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stats": map[string]interface{}{},
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats": stats,
	})
}

// handleAPISecurityReload reloads the security rules from database
func (wc *WebConsole) handleAPISecurityReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.securityDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Security database not initialized",
		})
		return
	}

	if err := wc.securityDB.ReloadRules(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	wc.logger.LogInfo("Security rules reloaded: %d active rules", wc.securityDB.GetCachedRuleCount())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "success",
		"active_rules": wc.securityDB.GetCachedRuleCount(),
	})
}

// handleAPIClientsStats returns global client statistics
func (wc *WebConsole) handleAPIClientsStats(w http.ResponseWriter, r *http.Request) {
	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	stats, err := wc.clientsDB.GetGlobalStats()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"stats":  stats,
	})
}

// handleAPIClientsTop returns top clients by bandwidth
func (wc *WebConsole) handleAPIClientsTop(w http.ResponseWriter, r *http.Request) {
	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	// Parse query parameters
	limit := 10
	days := 30
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := parseIntParam(l); err == nil && val > 0 {
			limit = val
		}
	}
	if d := r.URL.Query().Get("days"); d != "" {
		if val, err := parseIntParam(d); err == nil && val > 0 {
			days = val
		}
	}

	clients, err := wc.clientsDB.GetTopClients(limit, days)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"clients": clients,
	})
}

// handleAPIClientsDaily returns daily summary statistics
func (wc *WebConsole) handleAPIClientsDaily(w http.ResponseWriter, r *http.Request) {
	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if val, err := parseIntParam(d); err == nil && val > 0 {
			days = val
		}
	}

	summary, err := wc.clientsDB.GetDailySummary(days)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"summary": summary,
	})
}

// handleAPIClientsRecords returns recent client access records
func (wc *WebConsole) handleAPIClientsRecords(w http.ResponseWriter, r *http.Request) {
	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := parseIntParam(l); err == nil && val > 0 {
			limit = val
		}
	}

	records, err := wc.clientsDB.GetRecentRecords(limit)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"records": records,
	})
}

// handleAPIClientHistory returns access history for a specific client IP
func (wc *WebConsole) handleAPIClientHistory(w http.ResponseWriter, r *http.Request) {
	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "IP address required",
		})
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := parseIntParam(l); err == nil && val > 0 {
			limit = val
		}
	}

	records, err := wc.clientsDB.GetClientHistory(ip, limit)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"ip":      ip,
		"records": records,
	})
}

// handleAPIClientsCleanup manually triggers cleanup of old records
func (wc *WebConsole) handleAPIClientsCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.clientsDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Clients database not initialized",
		})
		return
	}

	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if val, err := parseIntParam(d); err == nil && val > 0 {
			days = val
		}
	}

	deleted, err := wc.clientsDB.CleanupOldRecords(days)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	wc.logger.LogInfo("Client records cleanup: %d records deleted (older than %d days)", deleted, days)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"deleted": deleted,
		"days":    days,
	})
}

// parseIntParam safely parses an integer from a string
func parseIntParam(s string) (int, error) {
	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	return val, err
}

// handleCluster renders the cluster replication page
func (wc *WebConsole) handleCluster(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderCluster(w, r, session)
}

// handleClusterEvents renders the cluster replication events page
func (wc *WebConsole) handleClusterEvents(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderClusterEvents(w, r, session)
}

// handleAPIClusterStatus returns cluster status and configuration
func (wc *WebConsole) handleAPIClusterStatus(w http.ResponseWriter, r *http.Request) {
	cfg := wc.config.Get()

	response := map[string]interface{}{
		"enabled":         cfg.ClusterEnabled,
		"node_name":       cfg.ClusterNodeName,
		"port":            cfg.ClusterPort,
		"auth_mode":       cfg.ClusterAuthMode,
		"auth_token":      cfg.ClusterAuthToken,
		"auth_token_set":  cfg.ClusterAuthToken != "",
		"auto_replicate":  cfg.ClusterAutoReplicate,
		"compression":     cfg.ClusterCompression,
		"bandwidth_limit": cfg.ClusterBandwidthLimit,
		"peers_count":     len(cfg.ClusterPeers),
		// OAuth settings (don't expose secret)
		"oauth_enabled":   cfg.ClusterOAuthEnabled,
		"oauth_token_url": cfg.ClusterOAuthTokenURL,
		"oauth_client_id": cfg.ClusterOAuthClientID,
		"oauth_scopes":    cfg.ClusterOAuthScopes,
	}

	// Include replication status if available
	if wc.replicationMgr != nil {
		response["replication"] = wc.replicationMgr.GetStatus()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIClusterStats returns cluster statistics
func (wc *WebConsole) handleAPIClusterStats(w http.ResponseWriter, r *http.Request) {
	if wc.clusterDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_nodes":         0,
			"online_nodes":        0,
			"total_replications":  0,
			"total_bytes_synced":  0,
			"total_files_synced":  0,
			"active_replications": 0,
		})
		return
	}

	stats, err := wc.clusterDB.GetClusterStats()
	if err != nil {
		wc.logger.LogError("Failed to get cluster stats: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAPIClusterNodes returns all cluster nodes
func (wc *WebConsole) handleAPIClusterNodes(w http.ResponseWriter, r *http.Request) {
	if wc.clusterDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"nodes": []interface{}{}})
		return
	}

	nodes, err := wc.clusterDB.GetAllNodes()
	if err != nil {
		wc.logger.LogError("Failed to get cluster nodes: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"nodes": nodes})
}

// handleAPIClusterNodeAdd adds a new peer node
func (wc *WebConsole) handleAPIClusterNodeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Enabled bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	if req.Name == "" || req.Address == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Name and address are required",
		})
		return
	}

	// Parse address to extract host and port
	cfg := wc.config.Get()
	host := req.Address
	port := cfg.ClusterPort

	if strings.Contains(req.Address, ":") {
		parts := strings.SplitN(req.Address, ":", 2)
		host = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}

	// Add to config
	newPeer := config.ClusterPeer{
		Name:    req.Name,
		Address: req.Address,
		Enabled: req.Enabled,
	}

	wc.config.Update(func(c *config.Config) {
		// Check for duplicate
		for i, p := range c.ClusterPeers {
			if p.Name == req.Name {
				// Update existing
				c.ClusterPeers[i] = newPeer
				return
			}
		}
		// Add new
		c.ClusterPeers = append(c.ClusterPeers, newPeer)
	})

	// Save config
	if err := wc.config.Save(wc.configPath); err != nil {
		wc.logger.LogError("Failed to save config: %v", err)
	}

	// Add to database
	if wc.clusterDB != nil {
		node := database.ClusterNode{
			Name:    req.Name,
			Address: host,
			Port:    port,
			Enabled: req.Enabled,
			Status:  "unknown",
		}
		if err := wc.clusterDB.UpsertNode(node); err != nil {
			wc.logger.LogError("Failed to add node to database: %v", err)
		}
	}

	wc.logger.LogInfo("Added cluster peer: %s (%s)", req.Name, req.Address)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Peer added successfully",
	})
}

// handleAPIClusterNodeRemove removes a peer node
func (wc *WebConsole) handleAPIClusterNodeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	if req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Name is required",
		})
		return
	}

	// Remove from config
	wc.config.Update(func(c *config.Config) {
		for i, p := range c.ClusterPeers {
			if p.Name == req.Name {
				c.ClusterPeers = append(c.ClusterPeers[:i], c.ClusterPeers[i+1:]...)
				break
			}
		}
	})

	// Save config
	if err := wc.config.Save(wc.configPath); err != nil {
		wc.logger.LogError("Failed to save config: %v", err)
	}

	// Remove from database
	if wc.clusterDB != nil {
		if err := wc.clusterDB.DeleteNode(req.Name); err != nil {
			wc.logger.LogError("Failed to remove node from database: %v", err)
		}
	}

	wc.logger.LogInfo("Removed cluster peer: %s", req.Name)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Peer removed successfully",
	})
}

// handleAPIClusterReplicate triggers replication
func (wc *WebConsole) handleAPIClusterReplicate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.replicationMgr == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Replication manager not available",
		})
		return
	}

	var req struct {
		Peer      string `json:"peer"`
		Direction string `json:"direction"` // "push" or "pull"
	}

	json.NewDecoder(r.Body).Decode(&req)

	go func() {
		var err error
		if req.Peer != "" {
			// Replicate to specific peer
			if req.Direction == "pull" {
				err = wc.replicationMgr.PullFromPeer(req.Peer)
			} else {
				err = wc.replicationMgr.ManualReplicate(req.Peer)
			}
		} else {
			// Replicate to all peers
			err = wc.replicationMgr.ReplicateToPeers()
		}
		if err != nil {
			wc.logger.LogError("Replication failed: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Replication started",
	})
}

// handleAPIClusterStopReplication stops any running replication
func (wc *WebConsole) handleAPIClusterStopReplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if wc.replicationMgr == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Replication manager not available",
		})
		return
	}

	if !wc.replicationMgr.IsRunning() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "not_running",
			"message": "No replication is currently running",
		})
		return
	}

	if err := wc.replicationMgr.StopReplication(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "stopping",
		"message": "Replication stop requested",
	})
}

// handleAPIClusterHistory returns replication history
func (wc *WebConsole) handleAPIClusterHistory(w http.ResponseWriter, r *http.Request) {
	if wc.clusterDB == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}})
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	events, err := wc.clusterDB.GetRecentEvents(limit)
	if err != nil {
		wc.logger.LogError("Failed to get replication events: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
}

// handleAPIClusterOAuth handles OAuth configuration updates
func (wc *WebConsole) handleAPIClusterOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AuthMode          string `json:"auth_mode"`
		AuthToken         string `json:"auth_token"`
		OAuthEnabled      bool   `json:"oauth_enabled"`
		OAuthTokenURL     string `json:"oauth_token_url"`
		OAuthClientID     string `json:"oauth_client_id"`
		OAuthClientSecret string `json:"oauth_client_secret"`
		OAuthScopes       string `json:"oauth_scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	// Update config
	wc.config.Update(func(c *config.Config) {
		if req.AuthMode != "" {
			c.ClusterAuthMode = req.AuthMode
		}
		if req.AuthToken != "" {
			c.ClusterAuthToken = req.AuthToken
		}
		c.ClusterOAuthEnabled = req.OAuthEnabled
		if req.OAuthTokenURL != "" {
			c.ClusterOAuthTokenURL = req.OAuthTokenURL
		}
		if req.OAuthClientID != "" {
			c.ClusterOAuthClientID = req.OAuthClientID
		}
		if req.OAuthClientSecret != "" {
			c.ClusterOAuthSecret = req.OAuthClientSecret
		}
		if req.OAuthScopes != "" {
			c.ClusterOAuthScopes = req.OAuthScopes
		}
	})

	// Save config
	if err := wc.config.Save(wc.configPath); err != nil {
		wc.logger.LogError("Failed to save OAuth config: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to save configuration",
		})
		return
	}

	wc.logger.LogInfo("Cluster OAuth settings updated (auth_mode: %s, oauth_enabled: %v)", req.AuthMode, req.OAuthEnabled)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "OAuth settings saved successfully",
	})
}

// handleAPIClusterToggle handles toggling cluster settings (enabled, auto_replicate)
func (wc *WebConsole) handleAPIClusterToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Setting string `json:"setting"`
		Value   bool   `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	// Update config based on setting
	switch req.Setting {
	case "enabled":
		wc.config.Update(func(c *config.Config) {
			c.ClusterEnabled = req.Value
		})
		wc.logger.LogInfo("Cluster replication %s via web console", map[bool]string{true: "enabled", false: "disabled"}[req.Value])

	case "auto_replicate":
		wc.config.Update(func(c *config.Config) {
			c.ClusterAutoReplicate = req.Value
		})
		wc.logger.LogInfo("Cluster auto-replicate %s via web console", map[bool]string{true: "enabled", false: "disabled"}[req.Value])

	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Unknown setting: " + req.Setting,
		})
		return
	}

	// Save config
	if err := wc.config.Save(wc.configPath); err != nil {
		wc.logger.LogError("Failed to save cluster toggle config: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to save configuration",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Setting updated successfully",
	})
}

// handleAPIClusterSettings handles updating cluster settings including auth token
func (wc *WebConsole) handleAPIClusterSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeName       string `json:"node_name"`
		Port           int    `json:"port"`
		AuthToken      string `json:"auth_token"`
		Compression    string `json:"compression"`
		BandwidthLimit int    `json:"bandwidth_limit"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid request body",
		})
		return
	}

	// Validate node name
	if req.NodeName == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Node name is required",
		})
		return
	}

	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Port must be between 1 and 65535",
		})
		return
	}

	// Validate compression
	validCompression := map[string]bool{"zstd": true, "gzip": true, "none": true}
	if req.Compression != "" && !validCompression[req.Compression] {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Invalid compression type. Must be zstd, gzip, or none",
		})
		return
	}

	// Update config
	wc.config.Update(func(c *config.Config) {
		c.ClusterNodeName = req.NodeName
		c.ClusterPort = req.Port
		if req.AuthToken != "" {
			c.ClusterAuthToken = req.AuthToken
		}
		if req.Compression != "" {
			c.ClusterCompression = req.Compression
		}
		if req.BandwidthLimit >= 0 {
			c.ClusterBandwidthLimit = req.BandwidthLimit
		}
	})

	wc.logger.LogInfo("Cluster settings updated via web console: node=%s, port=%d", req.NodeName, req.Port)

	// Save config
	if err := wc.config.Save(wc.configPath); err != nil {
		wc.logger.LogError("Failed to save cluster settings: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to save configuration",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Cluster settings saved successfully",
	})
}

// handleAPIGPGStatus returns the status of the GPG key
func (wc *WebConsole) handleAPIGPGStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := map[string]interface{}{
		"key_exists":  false,
		"key_id":      "",
		"key_name":    "",
		"key_email":   "",
		"key_created": "",
		"fingerprint": "",
	}

	// Create GPGManager instance
	gpgMgr := gpg.NewGPGManager(wc.config, wc.logger)

	// Check if keys exist
	if !gpgMgr.KeyExists() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Try to load key and get info
	keyInfo, err := gpgMgr.GetKeyInfo()
	if err != nil {
		// Key files exist but can't read info
		cfg := wc.config.Get()
		result["key_exists"] = true
		result["key_name"] = cfg.GPGKeyName
		result["key_email"] = cfg.GPGKeyEmail
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	result["key_exists"] = true
	result["key_id"] = keyInfo["keyid"]
	result["key_name"] = keyInfo["name"]
	result["key_email"] = keyInfo["email"]
	result["key_created"] = keyInfo["created"]
	result["fingerprint"] = keyInfo["fingerprint"]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPIGPGGenerate generates a new GPG key using pure Go
func (wc *WebConsole) handleAPIGPGGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		KeyName        string `json:"key_name"`
		KeyEmail       string `json:"key_email"`
		KeyComment     string `json:"key_comment"`
		PrivateKeyPath string `json:"private_key_path"`
		PublicKeyPath  string `json:"public_key_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	if req.KeyName == "" || req.KeyEmail == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Key name and email are required",
		})
		return
	}

	// Update config with requested paths if provided
	privateKeyPath := req.PrivateKeyPath
	publicKeyPath := req.PublicKeyPath
	if privateKeyPath != "" || publicKeyPath != "" {
		wc.config.Update(func(c *config.Config) {
			if privateKeyPath != "" {
				c.GPGPrivateKeyPath = privateKeyPath
			}
			if publicKeyPath != "" {
				c.GPGPublicKeyPath = publicKeyPath
			}
		})
	}

	// Create GPGManager instance
	gpgMgr := gpg.NewGPGManager(wc.config, wc.logger)

	// Generate the key using pure Go
	if err := gpgMgr.GenerateKey(req.KeyName, req.KeyComment, req.KeyEmail); err != nil {
		wc.logger.LogError("GPG key generation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Key generation failed: %v", err),
		})
		return
	}

	// Update config with key info
	wc.config.Update(func(c *config.Config) {
		c.GPGKeyName = req.KeyName
		c.GPGKeyEmail = req.KeyEmail
		c.GPGKeyComment = req.KeyComment
	})
	wc.config.Save(wc.configPath)

	session := wc.getSession(r)
	wc.logger.LogInfo("User %s generated new GPG key: %s <%s>", session.Username, req.KeyName, req.KeyEmail)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "GPG key generated successfully",
	})
}

// DirSizeCache holds cached directory sizes
type DirSizeCache struct {
	Pool      []DirSizeEntry `json:"pool"`
	Dists     []DirSizeEntry `json:"dists"`
	UpdatedAt string         `json:"updated_at"`
	mu        sync.RWMutex
}

// DirSizeEntry represents a directory and its size
type DirSizeEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

var dirSizeCache = &DirSizeCache{}

// handleAPIRepositorySizes returns sizes of pool and dists subdirectories from cache
func (wc *WebConsole) handleAPIRepositorySizes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to load from cache first
	dirSizeCache.mu.RLock()
	hasCache := len(dirSizeCache.Pool) > 0 || len(dirSizeCache.Dists) > 0
	dirSizeCache.mu.RUnlock()

	if !hasCache {
		// Try to load from cache file
		wc.loadDirSizeCache()
	}

	dirSizeCache.mu.RLock()
	defer dirSizeCache.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pool":       dirSizeCache.Pool,
		"dists":      dirSizeCache.Dists,
		"updated_at": dirSizeCache.UpdatedAt,
	})
}

// getDirSizeCachePath returns the path to the cache file
func (wc *WebConsole) getDirSizeCachePath() string {
	cfg := wc.config.Get()
	dbPath := cfg.DatabasePath
	if dbPath == "" {
		dbPath = filepath.Dir(wc.configPath)
	}
	return filepath.Join(dbPath, "dir_sizes_cache.json")
}

// loadDirSizeCache loads directory sizes from cache file
func (wc *WebConsole) loadDirSizeCache() {
	cachePath := wc.getDirSizeCachePath()
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return
	}

	var cache DirSizeCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return
	}

	dirSizeCache.mu.Lock()
	dirSizeCache.Pool = cache.Pool
	dirSizeCache.Dists = cache.Dists
	dirSizeCache.UpdatedAt = cache.UpdatedAt
	dirSizeCache.mu.Unlock()
}

// saveDirSizeCache saves directory sizes to cache file
func (wc *WebConsole) saveDirSizeCache() error {
	cachePath := wc.getDirSizeCachePath()

	dirSizeCache.mu.RLock()
	data, err := json.MarshalIndent(map[string]interface{}{
		"pool":       dirSizeCache.Pool,
		"dists":      dirSizeCache.Dists,
		"updated_at": dirSizeCache.UpdatedAt,
	}, "", "  ")
	dirSizeCache.mu.RUnlock()

	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0644)
}

// scanDirSizes scans directory sizes and updates cache
func (wc *WebConsole) scanDirSizes() {
	cfg := wc.config.Get()
	repoPath := cfg.RepositoryPath

	wc.logger.LogInfo("Starting repository directory size scan...")

	getSubdirSizes := func(parentDir string) []DirSizeEntry {
		var sizes []DirSizeEntry
		dirPath := filepath.Join(repoPath, parentDir)

		entries, err := os.ReadDir(dirPath)
		if err != nil {
			return sizes
		}

		for _, entry := range entries {
			if entry.IsDir() {
				subPath := filepath.Join(dirPath, entry.Name())
				size := getDirSize(subPath)
				sizes = append(sizes, DirSizeEntry{
					Name: entry.Name(),
					Size: size,
				})
			}
		}
		return sizes
	}

	poolSizes := getSubdirSizes("pool")
	distsSizes := getSubdirSizes("dists")

	dirSizeCache.mu.Lock()
	dirSizeCache.Pool = poolSizes
	dirSizeCache.Dists = distsSizes
	dirSizeCache.UpdatedAt = time.Now().Format(time.RFC3339)
	dirSizeCache.mu.Unlock()

	if err := wc.saveDirSizeCache(); err != nil {
		wc.logger.LogError("Failed to save directory size cache: %v", err)
	} else {
		wc.logger.LogInfo("Repository directory size scan completed and cached")
	}
}

// startDirSizeScanner starts the background directory size scanner
func (wc *WebConsole) startDirSizeScanner() {
	// Load cache on startup
	wc.loadDirSizeCache()

	// Run initial scan in background
	go wc.scanDirSizes()

	// Run scan every 30 minutes
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			wc.scanDirSizes()
		}
	}()
}

// handleAPIRepositoryScan triggers a manual directory size scan
func (wc *WebConsole) handleAPIRepositoryScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Run scan in background
	go wc.scanDirSizes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Directory size scan started",
	})
}

// getDirSize calculates total size of a directory recursively
func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// handleRepositoriesStatus renders the repositories status page
func (wc *WebConsole) handleRepositoriesStatus(w http.ResponseWriter, r *http.Request) {
	session := wc.getSession(r)
	wc.renderRepositoriesStatus(w, r, session)
}
