package api

import (
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/metrics"
	pkgmanager "activedebiansync/package"
	"activedebiansync/server"
	"activedebiansync/sync"
	"activedebiansync/utils"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// GPGKeyProvider interface pour récupérer la clé GPG
type GPGKeyProvider interface {
	GetPublicKeyForWeb() (string, error)
	IsEnabled() bool
	GetKeyInfo() (map[string]string, error)
	GenerateKey(name, comment, email string) error
	SignAllReleaseFiles() error
	ExportPublicKey(outputPath string) error
	KeyExists() bool
	IsLoaded() bool
	InitializeOrLoadKey() (bool, error)
	GenerateClientInstructions(serverURL string) string
}

// MirrorStatsProvider interface pour récupérer les stats des miroirs
type MirrorStatsProvider interface {
	GetMirrorStats() interface{}
}

// RestAPI gère l'API REST pour les statistiques et le monitoring
type RestAPI struct {
	config            *config.Config
	logger            *utils.Logger
	syncer            *sync.Syncer
	httpServer        *server.HTTPServer
	pkgManager        *pkgmanager.PackageManager
	gpgManager        GPGKeyProvider
	mirrorManager     MirrorStatsProvider
	prometheusMetrics *metrics.PrometheusMetrics
	apiServer         *http.Server
	searchDB          *database.PackageSearchDB
}

// StatusResponse représente la réponse de status général
type StatusResponse struct {
	Status            string                 `json:"status"`
	Uptime            string                 `json:"uptime"`
	Version           string                 `json:"version"`
	SyncStats         *sync.SyncStats        `json:"sync_stats"`
	ServerStats       *server.ServerStats    `json:"server_stats"`
	DiskSpace         *utils.DiskSpaceInfo   `json:"disk_space"`
	UpdatesAvailable  bool                   `json:"updates_available"`
	RepositorySize    int64                  `json:"repository_size_bytes"`
	Clients           []server.ClientInfo    `json:"clients"`
}

var startTime = time.Now()

// NewRestAPI crée une nouvelle instance de l'API REST
func NewRestAPI(cfg *config.Config, logger *utils.Logger, syncer *sync.Syncer, httpServer *server.HTTPServer, pkgManager *pkgmanager.PackageManager, gpgManager GPGKeyProvider, mirrorManager MirrorStatsProvider) *RestAPI {
	// Créer les métriques Prometheus
	prometheusMetrics := metrics.NewPrometheusMetrics(cfg, syncer, httpServer)

	return &RestAPI{
		config:            cfg,
		logger:            logger,
		syncer:            syncer,
		httpServer:        httpServer,
		pkgManager:        pkgManager,
		gpgManager:        gpgManager,
		mirrorManager:     mirrorManager,
		prometheusMetrics: prometheusMetrics,
	}
}

// Start démarre le serveur API REST
func (api *RestAPI) Start(ctx context.Context) error {
	cfg := api.config.Get()

	if !cfg.APIEnabled {
		api.logger.LogInfo("REST API is disabled")
		return nil
	}

	mux := http.NewServeMux()

	// Enregistrer les routes
	mux.HandleFunc("/api/status", api.withIPFilter(api.handleStatus))
	mux.HandleFunc("/api/sync/stats", api.withIPFilter(api.handleSyncStats))
	mux.HandleFunc("/api/sync/trigger", api.withIPFilter(api.handleSyncTrigger))
	mux.HandleFunc("/api/server/stats", api.withIPFilter(api.handleServerStats))
	mux.HandleFunc("/api/clients", api.withIPFilter(api.handleClients))
	mux.HandleFunc("/api/disk", api.withIPFilter(api.handleDiskSpace))
	mux.HandleFunc("/api/updates/check", api.withIPFilter(api.handleCheckUpdates))
	mux.HandleFunc("/api/health", api.handleHealth) // Health check sans restriction

	// Routes pour la gestion des packages personnalisés
	mux.HandleFunc("/api/packages/upload", api.withIPFilter(api.handlePackageUpload))
	mux.HandleFunc("/api/packages/list", api.withIPFilter(api.handlePackageList))
	mux.HandleFunc("/api/packages/remove", api.withIPFilter(api.handlePackageRemove))
	mux.HandleFunc("/api/packages/regenerate", api.withIPFilter(api.handlePackageRegenerate))

	// Routes GPG
	mux.HandleFunc("/api/gpg-key", api.handleGPGKey)              // Sans restriction pour permettre aux clients de télécharger
	mux.HandleFunc("/api/gpg/info", api.withIPFilter(api.handleGPGInfo))
	mux.HandleFunc("/api/gpg/generate", api.withIPFilter(api.handleGPGGenerate))
	mux.HandleFunc("/api/gpg/sign", api.withIPFilter(api.handleGPGSign))
	mux.HandleFunc("/api/gpg/export", api.withIPFilter(api.handleGPGExport))
	mux.HandleFunc("/api/gpg/status", api.withIPFilter(api.handleGPGStatus))
	mux.HandleFunc("/api/gpg/instructions", api.handleGPGInstructions) // Sans restriction

	// Route pour les statistiques des miroirs
	mux.HandleFunc("/api/mirrors", api.withIPFilter(api.handleMirrors))

	// Routes pour les statistiques avancées
	mux.HandleFunc("/api/stats/top-packages", api.withIPFilter(api.handleTopPackages))
	mux.HandleFunc("/api/stats/bandwidth", api.withIPFilter(api.handleBandwidth))
	mux.HandleFunc("/api/stats/anomalies", api.withIPFilter(api.handleAnomalies))
	mux.HandleFunc("/api/stats/disk-prediction", api.withIPFilter(api.handleDiskPrediction))

	// Routes pour l'optimisation du stockage
	mux.HandleFunc("/api/storage/deduplicate", api.withIPFilter(api.handleStorageDeduplicate))
	mux.HandleFunc("/api/storage/cleanup", api.withIPFilter(api.handleStorageCleanup))
	mux.HandleFunc("/api/storage/tier", api.withIPFilter(api.handleStorageTier))
	mux.HandleFunc("/api/storage/stats", api.withIPFilter(api.handleStorageStats))

	// Routes pour les mises à jour de packages (base de données)
	mux.HandleFunc("/api/updates/packages", api.withIPFilter(api.handlePackageUpdates))
	mux.HandleFunc("/api/updates/packages/recent", api.withIPFilter(api.handleRecentPackageUpdates))
	mux.HandleFunc("/api/updates/packages/stats", api.withIPFilter(api.handlePackageUpdatesStats))
	mux.HandleFunc("/api/updates/packages/today", api.withIPFilter(api.handleTodayPackageUpdates))
	mux.HandleFunc("/api/updates/packages/search", api.withIPFilter(api.handleSearchPackageUpdates))

	// Routes pour la recherche de packages (comme apt-file)
	mux.HandleFunc("/api/search", api.withIPFilter(api.handlePackageSearch))
	mux.HandleFunc("/api/search/file", api.withIPFilter(api.handleFileSearch))
	mux.HandleFunc("/api/search/package", api.withIPFilter(api.handlePackageNameSearch))
	mux.HandleFunc("/api/search/description", api.withIPFilter(api.handleDescriptionSearch))
	mux.HandleFunc("/api/search/package-files", api.withIPFilter(api.handlePackageFilesSearch))
	mux.HandleFunc("/api/search/package-info", api.withIPFilter(api.handlePackageInfoSearch))
	mux.HandleFunc("/api/search/status", api.withIPFilter(api.handleSearchStatus))

	// Route Prometheus metrics (sans restriction pour permettre scraping)
	mux.Handle("/metrics", promhttp.Handler())

	api.apiServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.APIListenAddr, cfg.APIPort),
		Handler: mux,
	}

	go func() {
		api.logger.LogInfo("Starting REST API on %s:%d", cfg.APIListenAddr, cfg.APIPort)
		if err := api.apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			api.logger.LogError("REST API server error: %v", err)
		}
	}()

	// Goroutine pour mettre à jour les métriques Prometheus périodiquement
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if api.prometheusMetrics != nil {
					api.prometheusMetrics.UpdateMetrics(int64(time.Since(startTime).Seconds()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Attendre l'arrêt
	<-ctx.Done()
	return api.Stop()
}

// Stop arrête le serveur API
func (api *RestAPI) Stop() error {
	if api.apiServer == nil {
		return nil
	}

	api.logger.LogInfo("Stopping REST API server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return api.apiServer.Shutdown(ctx)
}

// withIPFilter middleware pour filtrer les IPs autorisées
func (api *RestAPI) withIPFilter(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := api.config.Get()

		// Si l'API écoute sur 127.0.0.1, pas de restriction
		if cfg.APIListenAddr == "127.0.0.1" || cfg.APIListenAddr == "localhost" {
			next(w, r)
			return
		}

		// Si aucune IP n'est configurée, autoriser tout
		if len(cfg.APIAllowedIPs) == 0 {
			next(w, r)
			return
		}

		// Extraire l'IP du client
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// Vérifier X-Forwarded-For pour les proxies
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
			clientIP = strings.TrimSpace(clientIP)
		}

		// Parser l'IP du client
		parsedClientIP := net.ParseIP(clientIP)
		if parsedClientIP == nil {
			api.logger.LogError("Invalid client IP: %s", clientIP)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Vérifier si l'IP est autorisée (supporte IP simple et CIDR)
		allowed := false
		for _, allowedEntry := range cfg.APIAllowedIPs {
			// Vérifier si c'est une notation CIDR (contient /)
			if strings.Contains(allowedEntry, "/") {
				_, network, err := net.ParseCIDR(allowedEntry)
				if err != nil {
					api.logger.LogError("Invalid CIDR in api_allowed_ips: %s", allowedEntry)
					continue
				}
				if network.Contains(parsedClientIP) {
					allowed = true
					break
				}
			} else {
				// IP simple
				if clientIP == allowedEntry {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			api.logger.LogError("Unauthorized API access attempt from %s", clientIP)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// handleStatus retourne le status général
func (api *RestAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := api.config.Get()

	// Obtenir les statistiques
	syncStats := api.syncer.GetStats()
	serverStats := api.httpServer.GetStats()
	diskSpace, _ := utils.GetDiskUsage(cfg.RepositoryPath)
	clients := api.httpServer.GetClients()

	// Vérifier les mises à jour disponibles
	updatesAvailable, _ := api.syncer.CheckForUpdates()

	// Calculer la taille du dépôt
	repoSize := api.getRepositorySize(cfg.RepositoryPath)

	response := StatusResponse{
		Status:           "running",
		Uptime:           time.Since(startTime).String(),
		Version:          "1.0.0",
		SyncStats:        syncStats,
		ServerStats:      serverStats,
		DiskSpace:        diskSpace,
		UpdatesAvailable: updatesAvailable,
		RepositorySize:   repoSize,
		Clients:          clients,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleSyncStats retourne les statistiques de synchronisation
func (api *RestAPI) handleSyncStats(w http.ResponseWriter, r *http.Request) {
	stats := api.syncer.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleSyncTrigger déclenche une synchronisation manuelle
func (api *RestAPI) handleSyncTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.logger.LogInfo("Manual sync triggered via API")
	go api.syncer.Sync()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "triggered",
		"message": "Synchronization started",
	})
}

// handleServerStats retourne les statistiques du serveur HTTP
func (api *RestAPI) handleServerStats(w http.ResponseWriter, r *http.Request) {
	stats := api.httpServer.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleClients retourne la liste des clients connectés
func (api *RestAPI) handleClients(w http.ResponseWriter, r *http.Request) {
	clients := api.httpServer.GetClients()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

// handleDiskSpace retourne les informations d'espace disque
func (api *RestAPI) handleDiskSpace(w http.ResponseWriter, r *http.Request) {
	cfg := api.config.Get()
	diskSpace, err := utils.GetDiskUsage(cfg.RepositoryPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	repoSize := api.getRepositorySize(cfg.RepositoryPath)

	response := map[string]interface{}{
		"disk_space":      diskSpace,
		"repository_size": repoSize,
		"repository_size_formatted": utils.FormatBytes(uint64(repoSize)),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleCheckUpdates vérifie si des mises à jour sont disponibles
func (api *RestAPI) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	updatesAvailable, err := api.syncer.CheckForUpdates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"updates_available": updatesAvailable,
		"checked_at":        time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleHealth endpoint de santé simple
func (api *RestAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// getRepositorySize calcule la taille totale du dépôt
func (api *RestAPI) getRepositorySize(path string) int64 {
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

// handlePackageUpload gère l'upload d'un package .deb
func (api *RestAPI) handlePackageUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parser le multipart form (max 500MB)
	if err := r.ParseMultipartForm(500 << 20); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	// Récupérer le fichier
	file, header, err := r.FormFile("package")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Récupérer les paramètres
	release := r.FormValue("release")
	component := r.FormValue("component")
	architecture := r.FormValue("architecture")

	if release == "" || component == "" || architecture == "" {
		http.Error(w, "Missing parameters: release, component, architecture required", http.StatusBadRequest)
		return
	}

	api.logger.LogInfo("API: Uploading package %s to %s/%s/%s", header.Filename, release, component, architecture)

	// Créer un fichier temporaire
	tmpFile, err := os.CreateTemp("", "upload-*.deb")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temp file: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copier le fichier uploadé
	if _, err := io.Copy(tmpFile, file); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save file: %v", err), http.StatusInternalServerError)
		return
	}

	tmpFile.Close()

	// Ajouter le package au dépôt
	if err := api.pkgManager.AddPackage(tmpFile.Name(), release, component, architecture); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add package: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":       "success",
		"message":      "Package uploaded and indexes regenerated",
		"filename":     header.Filename,
		"release":      release,
		"component":    component,
		"architecture": architecture,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePackageList liste les packages personnalisés
func (api *RestAPI) handlePackageList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	release := r.URL.Query().Get("release")
	component := r.URL.Query().Get("component")
	architecture := r.URL.Query().Get("architecture")

	if release == "" || component == "" || architecture == "" {
		http.Error(w, "Missing parameters: release, component, architecture required", http.StatusBadRequest)
		return
	}

	packages, err := api.pkgManager.ListPackages(release, component, architecture)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list packages: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"release":      release,
		"component":    component,
		"architecture": architecture,
		"count":        len(packages),
		"packages":     packages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePackageRemove supprime un package
func (api *RestAPI) handlePackageRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		Package      string `json:"package"`
		Version      string `json:"version"`
		Release      string `json:"release"`
		Component    string `json:"component"`
		Architecture string `json:"architecture"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	if params.Package == "" || params.Version == "" || params.Release == "" || params.Component == "" || params.Architecture == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	api.logger.LogInfo("API: Removing package %s %s from %s/%s/%s", params.Package, params.Version, params.Release, params.Component, params.Architecture)

	if err := api.pkgManager.RemovePackage(params.Package, params.Version, params.Release, params.Component, params.Architecture); err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove package: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Package removed and indexes regenerated",
		"package": params.Package,
		"version": params.Version,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePackageRegenerate régénère les indexes
func (api *RestAPI) handlePackageRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		Release      string `json:"release"`
		Component    string `json:"component"`
		Architecture string `json:"architecture"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	if params.Release == "" || params.Component == "" || params.Architecture == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	api.logger.LogInfo("API: Regenerating indexes for %s/%s/%s", params.Release, params.Component, params.Architecture)

	if err := api.pkgManager.RegenerateIndexes(params.Release, params.Component, params.Architecture); err != nil {
		http.Error(w, fmt.Sprintf("Failed to regenerate indexes: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Indexes regenerated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGKey retourne la clé publique GPG pour les clients
func (api *RestAPI) handleGPGKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled", http.StatusNotFound)
		return
	}

	if api.gpgManager == nil {
		http.Error(w, "GPG manager not available", http.StatusInternalServerError)
		return
	}

	// Récupérer la clé publique
	publicKey, err := api.gpgManager.GetPublicKeyForWeb()
	if err != nil {
		api.logger.LogError("Failed to get public key: %v", err)
		http.Error(w, "Failed to retrieve public key", http.StatusInternalServerError)
		return
	}

	// Retourner la clé en format texte (PGP armored)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"gpg-key.asc\"")
	w.Write([]byte(publicKey))
}

// handleMirrors retourne les statistiques de tous les miroirs
func (api *RestAPI) handleMirrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	// Vérifier si le multi-miroir est activé
	if !cfg.MultiMirrorEnabled {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"multi_mirror_enabled": false,
			"message":              "Multi-mirror feature is not enabled",
		})
		return
	}

	if api.mirrorManager == nil {
		http.Error(w, "Mirror manager not available", http.StatusInternalServerError)
		return
	}

	// Récupérer les statistiques des miroirs
	stats := api.mirrorManager.GetMirrorStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"multi_mirror_enabled": true,
		"mirrors":              stats,
	})
}

// handlePackageUpdates retourne les mises à jour de packages avec pagination et filtres
func (api *RestAPI) handlePackageUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	updatesDB := api.syncer.GetUpdatesDB()
	if updatesDB == nil {
		http.Error(w, "Package updates database not available", http.StatusServiceUnavailable)
		return
	}

	// Parser les paramètres de requête
	query := r.URL.Query()
	opts := database.QueryOptions{}

	if release := query.Get("release"); release != "" {
		opts.Release = release
	}
	if component := query.Get("component"); component != "" {
		opts.Component = component
	}
	if arch := query.Get("architecture"); arch != "" {
		opts.Architecture = arch
	}
	if pkgName := query.Get("package"); pkgName != "" {
		opts.PackageName = pkgName
	}
	if since := query.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = &t
		} else if t, err := time.Parse("2006-01-02", since); err == nil {
			opts.Since = &t
		}
	}
	if until := query.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = &t
		} else if t, err := time.Parse("2006-01-02", until); err == nil {
			opts.Until = &t
		}
	}
	if limit := query.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	} else {
		opts.Limit = 100 // Default limit
	}
	if offset := query.Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			opts.Offset = o
		}
	}

	updates, err := updatesDB.GetUpdates(opts)
	if err != nil {
		api.logger.LogError("Failed to get package updates: %v", err)
		http.Error(w, "Failed to retrieve updates", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(updates),
		"limit":   opts.Limit,
		"offset":  opts.Offset,
		"updates": updates,
	})
}

// handleRecentPackageUpdates retourne les N dernières mises à jour
func (api *RestAPI) handleRecentPackageUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	updatesDB := api.syncer.GetUpdatesDB()
	if updatesDB == nil {
		http.Error(w, "Package updates database not available", http.StatusServiceUnavailable)
		return
	}

	// Parser le paramètre limit
	limit := 50 // Default
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	updates, err := updatesDB.GetRecentUpdates(limit)
	if err != nil {
		api.logger.LogError("Failed to get recent package updates: %v", err)
		http.Error(w, "Failed to retrieve updates", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(updates),
		"updates": updates,
	})
}

// handlePackageUpdatesStats retourne les statistiques des mises à jour
func (api *RestAPI) handlePackageUpdatesStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	updatesDB := api.syncer.GetUpdatesDB()
	if updatesDB == nil {
		http.Error(w, "Package updates database not available", http.StatusServiceUnavailable)
		return
	}

	stats, err := updatesDB.GetStats()
	if err != nil {
		api.logger.LogError("Failed to get package updates stats: %v", err)
		http.Error(w, "Failed to retrieve stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleTodayPackageUpdates retourne les mises à jour d'aujourd'hui
func (api *RestAPI) handleTodayPackageUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	updatesDB := api.syncer.GetUpdatesDB()
	if updatesDB == nil {
		http.Error(w, "Package updates database not available", http.StatusServiceUnavailable)
		return
	}

	updates, err := updatesDB.GetUpdatesToday()
	if err != nil {
		api.logger.LogError("Failed to get today's package updates: %v", err)
		http.Error(w, "Failed to retrieve updates", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"date":    time.Now().Format("2006-01-02"),
		"count":   len(updates),
		"updates": updates,
	})
}

// handleSearchPackageUpdates recherche des packages par nom
func (api *RestAPI) handleSearchPackageUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	updatesDB := api.syncer.GetUpdatesDB()
	if updatesDB == nil {
		http.Error(w, "Package updates database not available", http.StatusServiceUnavailable)
		return
	}

	// Le paramètre q est requis pour la recherche
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing required parameter: q", http.StatusBadRequest)
		return
	}

	opts := database.QueryOptions{
		PackageName: query,
		Limit:       100,
	}

	// Paramètres optionnels
	if release := r.URL.Query().Get("release"); release != "" {
		opts.Release = release
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	}

	updates, err := updatesDB.GetUpdates(opts)
	if err != nil {
		api.logger.LogError("Failed to search package updates: %v", err)
		http.Error(w, "Failed to search updates", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"count":   len(updates),
		"updates": updates,
	})
}

// SetSearchDB définit la base de données de recherche de packages
func (api *RestAPI) SetSearchDB(searchDB *database.PackageSearchDB) {
	api.searchDB = searchDB
}

// handlePackageSearch recherche des packages (multi-critères)
func (api *RestAPI) handlePackageSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	q := query.Get("q")
	if q == "" {
		http.Error(w, "Missing required parameter: q", http.StatusBadRequest)
		return
	}

	opts := database.SearchOptions{
		Query:        q,
		Release:      query.Get("release"),
		Component:    query.Get("component"),
		Architecture: query.Get("architecture"),
	}

	// Type de recherche (par défaut: tout)
	searchType := query.Get("type")
	switch searchType {
	case "name":
		opts.SearchName = true
	case "description":
		opts.SearchDesc = true
	case "file":
		opts.SearchFiles = true
	default:
		// Rechercher partout
		opts.SearchName = true
		opts.SearchDesc = true
		opts.SearchFiles = true
	}

	if exact := query.Get("exact"); exact == "true" || exact == "1" {
		opts.ExactMatch = true
	}

	if limit := query.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	} else {
		opts.Limit = 100
	}

	results, err := api.searchDB.Search(opts)
	if err != nil {
		api.logger.LogError("Package search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   q,
		"type":    searchType,
		"count":   len(results),
		"results": results,
	})
}

// handleFileSearch recherche des packages par fichier (comme apt-file search)
func (api *RestAPI) handleFileSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	filePath := query.Get("path")
	if filePath == "" {
		filePath = query.Get("q")
	}
	if filePath == "" {
		http.Error(w, "Missing required parameter: path or q", http.StatusBadRequest)
		return
	}

	release := query.Get("release")
	arch := query.Get("architecture")

	limit := 100
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	results, err := api.searchDB.SearchByFile(filePath, release, arch, limit)
	if err != nil {
		api.logger.LogError("File search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file_path": filePath,
		"count":     len(results),
		"results":   results,
	})
}

// handlePackageNameSearch recherche des packages par nom
func (api *RestAPI) handlePackageNameSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	name := query.Get("name")
	if name == "" {
		name = query.Get("q")
	}
	if name == "" {
		http.Error(w, "Missing required parameter: name or q", http.StatusBadRequest)
		return
	}

	release := query.Get("release")

	limit := 100
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	results, err := api.searchDB.SearchByName(name, release, limit)
	if err != nil {
		api.logger.LogError("Package name search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    name,
		"count":   len(results),
		"results": results,
	})
}

// handleDescriptionSearch recherche des packages par description
func (api *RestAPI) handleDescriptionSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	desc := query.Get("desc")
	if desc == "" {
		desc = query.Get("q")
	}
	if desc == "" {
		http.Error(w, "Missing required parameter: desc or q", http.StatusBadRequest)
		return
	}

	release := query.Get("release")

	limit := 100
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	results, err := api.searchDB.SearchByDescription(desc, release, limit)
	if err != nil {
		api.logger.LogError("Description search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"description": desc,
		"count":       len(results),
		"results":     results,
	})
}

// handlePackageFilesSearch liste les fichiers contenus dans un package (comme apt-file list)
func (api *RestAPI) handlePackageFilesSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	pkgName := query.Get("package")
	if pkgName == "" {
		pkgName = query.Get("name")
	}
	if pkgName == "" {
		http.Error(w, "Missing required parameter: package or name", http.StatusBadRequest)
		return
	}

	release := query.Get("release")
	arch := query.Get("architecture")

	files, err := api.searchDB.GetPackageFiles(pkgName, release, arch)
	if err != nil {
		api.logger.LogError("Package files search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"package": pkgName,
		"count":   len(files),
		"files":   files,
	})
}

// handlePackageInfoSearch retourne les informations détaillées d'un package
func (api *RestAPI) handlePackageInfoSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.PackageSearchEnabled {
		http.Error(w, "Package search is disabled", http.StatusServiceUnavailable)
		return
	}

	if api.searchDB == nil {
		http.Error(w, "Search database not available", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	pkgName := query.Get("package")
	if pkgName == "" {
		pkgName = query.Get("name")
	}
	if pkgName == "" {
		http.Error(w, "Missing required parameter: package or name", http.StatusBadRequest)
		return
	}

	release := query.Get("release")
	arch := query.Get("architecture")

	info, err := api.searchDB.GetPackageInfo(pkgName, release, arch)
	if err != nil {
		api.logger.LogError("Package info search failed: %v", err)
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	if info == nil {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	// Récupérer aussi les fichiers si disponibles
	files, _ := api.searchDB.GetPackageFiles(pkgName, release, arch)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"package":     info,
		"files":       files,
		"files_count": len(files),
	})
}

// handleSearchStatus retourne le statut de l'indexation de la recherche
func (api *RestAPI) handleSearchStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	response := map[string]interface{}{
		"enabled": cfg.PackageSearchEnabled,
	}

	if !cfg.PackageSearchEnabled {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if api.searchDB == nil {
		response["status"] = "not_initialized"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Récupérer les statistiques
	stats, err := api.searchDB.GetSearchStats()
	if err != nil {
		api.logger.LogError("Failed to get search stats: %v", err)
		response["status"] = "error"
		response["error"] = err.Error()
	} else {
		response["status"] = "ready"
		response["stats"] = stats
	}

	// Récupérer le statut d'indexation par release/component/arch
	indexStatus, err := api.searchDB.GetIndexStatus()
	if err == nil {
		response["index_status"] = indexStatus
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGInfo retourne les informations sur la clé GPG
func (api *RestAPI) handleGPGInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled", http.StatusNotFound)
		return
	}

	if api.gpgManager == nil {
		http.Error(w, "GPG manager not available", http.StatusInternalServerError)
		return
	}

	info, err := api.gpgManager.GetKeyInfo()
	if err != nil {
		api.logger.LogError("Failed to get GPG key info: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get key info: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"enabled":  true,
		"key_info": info,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGGenerate génère une nouvelle paire de clés GPG
func (api *RestAPI) handleGPGGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled in configuration", http.StatusBadRequest)
		return
	}

	if api.gpgManager == nil {
		http.Error(w, "GPG manager not available", http.StatusInternalServerError)
		return
	}

	// Parser les paramètres
	var params struct {
		Force   bool   `json:"force"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Comment string `json:"comment"`
	}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		// Pas de body ou erreur de parsing - c'est OK, on utilise les valeurs par défaut
	}

	// Vérifier si une clé existe déjà
	if api.gpgManager.KeyExists() && !params.Force {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "GPG key already exists. Use 'force: true' to regenerate",
		})
		return
	}

	name := params.Name
	if name == "" {
		name = cfg.GPGKeyName
		if name == "" {
			name = "ActiveDebianSync Repository"
		}
	}
	email := params.Email
	if email == "" {
		email = cfg.GPGKeyEmail
		if email == "" {
			email = "repo@activedebiansync.local"
		}
	}
	comment := params.Comment
	if comment == "" {
		comment = cfg.GPGKeyComment
		if comment == "" {
			comment = "Automatic repository signing key"
		}
	}

	api.logger.LogInfo("API: Generating new GPG key for %s <%s>", name, email)

	if err := api.gpgManager.GenerateKey(name, comment, email); err != nil {
		api.logger.LogError("Failed to generate GPG key: %v", err)
		http.Error(w, fmt.Sprintf("Failed to generate key: %v", err), http.StatusInternalServerError)
		return
	}

	// Récupérer les infos de la nouvelle clé
	info, _ := api.gpgManager.GetKeyInfo()

	response := map[string]interface{}{
		"status":   "success",
		"message":  "GPG key pair generated successfully",
		"key_info": info,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGSign déclenche la signature de tous les fichiers Release
func (api *RestAPI) handleGPGSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled", http.StatusBadRequest)
		return
	}

	if api.gpgManager == nil {
		http.Error(w, "GPG manager not available", http.StatusInternalServerError)
		return
	}

	if !api.gpgManager.KeyExists() {
		http.Error(w, "GPG key does not exist. Generate a key first", http.StatusBadRequest)
		return
	}

	api.logger.LogInfo("API: Signing all Release files")

	if err := api.gpgManager.SignAllReleaseFiles(); err != nil {
		api.logger.LogError("Failed to sign Release files: %v", err)
		http.Error(w, fmt.Sprintf("Failed to sign Release files: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "All Release files signed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGExport exporte la clé publique GPG
func (api *RestAPI) handleGPGExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled", http.StatusNotFound)
		return
	}

	if api.gpgManager == nil {
		http.Error(w, "GPG manager not available", http.StatusInternalServerError)
		return
	}

	if !api.gpgManager.KeyExists() {
		http.Error(w, "GPG key does not exist", http.StatusNotFound)
		return
	}

	publicKey, err := api.gpgManager.GetPublicKeyForWeb()
	if err != nil {
		api.logger.LogError("Failed to export GPG key: %v", err)
		http.Error(w, fmt.Sprintf("Failed to export key: %v", err), http.StatusInternalServerError)
		return
	}

	// Déterminer le format de sortie
	format := r.URL.Query().Get("format")
	if format == "json" {
		info, _ := api.gpgManager.GetKeyInfo()
		response := map[string]interface{}{
			"public_key": publicKey,
			"key_info":   info,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Format texte par défaut (armored PGP key)
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("Content-Disposition", "attachment; filename=\"activedebiansync.asc\"")
	w.Write([]byte(publicKey))
}

// handleGPGStatus retourne le statut complet du système GPG
func (api *RestAPI) handleGPGStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	response := map[string]interface{}{
		"enabled": cfg.GPGSigningEnabled,
	}

	if !cfg.GPGSigningEnabled {
		response["status"] = "disabled"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if api.gpgManager == nil {
		response["status"] = "not_initialized"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	keyExists := api.gpgManager.KeyExists()
	keyLoaded := api.gpgManager.IsLoaded()

	response["key_exists"] = keyExists
	response["key_loaded"] = keyLoaded
	response["private_key_path"] = cfg.GPGPrivateKeyPath
	response["public_key_path"] = cfg.GPGPublicKeyPath

	if keyExists && keyLoaded {
		response["status"] = "ready"
		if info, err := api.gpgManager.GetKeyInfo(); err == nil {
			response["key_info"] = info
		}
	} else if keyExists && !keyLoaded {
		response["status"] = "key_not_loaded"
	} else {
		response["status"] = "no_key"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGPGInstructions retourne les instructions d'installation pour les clients APT
func (api *RestAPI) handleGPGInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()

	if !cfg.GPGSigningEnabled {
		http.Error(w, "GPG signing is not enabled", http.StatusNotFound)
		return
	}

	if api.gpgManager == nil || !api.gpgManager.KeyExists() {
		http.Error(w, "GPG key not available", http.StatusNotFound)
		return
	}

	// Construire l'URL du serveur
	serverURL := r.URL.Query().Get("server_url")
	if serverURL == "" {
		// Essayer de deviner l'URL depuis le header Host
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		}
		host := r.Host
		if host == "" {
			host = fmt.Sprintf("localhost:%d", cfg.HTTPPort)
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, host)
	}

	// Déterminer le format de sortie
	format := r.URL.Query().Get("format")
	if format == "json" {
		instructions := api.gpgManager.GenerateClientInstructions(serverURL)
		response := map[string]interface{}{
			"server_url":   serverURL,
			"instructions": instructions,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Format texte (markdown)
	instructions := api.gpgManager.GenerateClientInstructions(serverURL)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write([]byte(instructions))
}
