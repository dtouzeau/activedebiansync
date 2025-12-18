package sync

import (
	"activedebiansync/articarepos"
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/integrity"
	"activedebiansync/mirrors"
	"activedebiansync/stats"
	"activedebiansync/storage"
	"activedebiansync/utils"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ulikunitz/xz"
)

type GPGSigner interface {
	SignAllReleaseFiles() error
	IsEnabled() bool
}
type PackageIndexer interface {
	RegenerateIndexes(release, component, architecture string) error
}

// CVEScannerInterface defines the interface for CVE scanning
type CVEScannerInterface interface {
	ShouldScanAfterSync() bool
	Scan(release, component, architecture string, includePackages bool) (interface{}, error)
}

// ReplicationManagerInterface defines the interface for cluster replication
type ReplicationManagerInterface interface {
	ReplicateToPeers() error
	IsRunning() bool
}

// Syncer gère la synchronisation des dépôts Debian
type Syncer struct {
	config         *config.Config
	logger         *utils.Logger
	gpgManager     GPGSigner
	packageIndexer PackageIndexer
	cveScanner     CVEScannerInterface
	replicationMgr ReplicationManagerInterface
	mirrorManager  *mirrors.MirrorManager
	httpClient     *http.Client
	validator      *integrity.Validator
	analytics      *stats.Analytics
	optimizer      *storage.Optimizer
	updatesDB      *database.UpdatesDB
	searchDB       *database.PackageSearchDB
	eventsDB       *database.EventsDB
	isRunning      atomic.Bool
	stopRequested  atomic.Bool
	lastSync       time.Time
	lastError      error
	stats          *SyncStats
	activity       *SyncActivity
	rateLimiter    *utils.RateLimiter
	mu             sync.RWMutex
	stopChan       chan struct{}
	stoppedChan    chan struct{}
}

// DownloadJob représente un job de téléchargement
type DownloadJob struct {
	URL          string
	LocalPath    string
	ReleaseName  string // Nom de la release pour la validation d'intégrité
	RelativePath string // Chemin relatif pour la validation d'intégrité
	// Package info for database recording
	PackageName        string
	PackageVersion     string
	PackageDescription string
	PackageSize        int64
	Component          string
	Architecture       string
}

// DownloadResult représente le résultat d'un téléchargement
type DownloadResult struct {
	Job   DownloadJob
	Error error
}

// FailedFile represents a file that failed to download
type FailedFile struct {
	URL       string    `json:"url"`
	LocalPath string    `json:"local_path"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
	Suite     string    `json:"suite,omitempty"`
	Component string    `json:"component,omitempty"`
}

// SyncActivity represents the current sync activity
type SyncActivity struct {
	Action       string    `json:"action"`        // e.g., "downloading", "verifying", "indexing"
	File         string    `json:"file"`          // Current file being processed
	Suite        string    `json:"suite"`         // Current suite (e.g., "bookworm")
	Component    string    `json:"component"`     // Current component (e.g., "main")
	Progress     int       `json:"progress"`      // Progress percentage (0-100)
	BytesDone    int64     `json:"bytes_done"`    // Bytes downloaded in current session
	FilesCount   int       `json:"files_count"`   // Total files to process in current batch
	FilesDone    int       `json:"files_done"`    // Files completed in current batch
	SessionFiles int64     `json:"session_files"` // Total files downloaded in this sync session
	SessionBytes int64     `json:"session_bytes"` // Total bytes downloaded in this sync session
	Timestamp    time.Time `json:"timestamp"`     // When this activity was recorded
	mu           sync.RWMutex
}

// SyncStats contient les statistiques de synchronisation
type SyncStats struct {
	TotalFiles       int64        `json:"total_files"`
	TotalBytes       int64        `json:"total_bytes"`
	FailedFiles      int64        `json:"failed_files"`
	FailedFilesList  []FailedFile `json:"failed_files_list,omitempty"`
	LastSyncStart    time.Time    `json:"last_sync_start"`
	LastSyncEnd      time.Time    `json:"last_sync_end"`
	LastSyncDuration string       `json:"last_sync_duration"`
	IsRunning        bool         `json:"is_running"`
	LastError        string       `json:"last_error,omitempty"`
	DiskError        bool         `json:"disk_error"`
	DiskErrorMessage string       `json:"disk_error_message,omitempty"`
	mu               sync.RWMutex
}

// NewSyncer crée une nouvelle instance de Syncer
func NewSyncer(cfg *config.Config, logger *utils.Logger, gpgManager GPGSigner) *Syncer {
	cfgData := cfg.Get()
	bandwidthLimit := int64(cfgData.DownloadBandwidthLimit) * 1024 // Convertir KB/s en bytes/s

	// Créer le mirror manager
	mirrorManager := mirrors.NewMirrorManager(cfg, logger)

	// Créer le HTTP client avec support de l'interface réseau et du proxy
	httpClientConfig := utils.HTTPClientConfig{
		NetworkInterface: cfgData.NetworkInterface,
		ProxyEnabled:     cfgData.ProxyEnabled,
		ProxyURL:         cfgData.ProxyURL,
		ProxyUsername:    cfgData.ProxyUsername,
		ProxyPassword:    cfgData.ProxyPassword,
		Timeout:          120 * time.Second, // 2 minutes pour les gros fichiers
	}

	httpClient, err := utils.NewHTTPClient(httpClientConfig)
	if err != nil {
		logger.LogError("Failed to create HTTP client: %v, using default", err)
		httpClient = &http.Client{
			Timeout: 120 * time.Second,
		}
	} else {
		if cfgData.NetworkInterface != "" {
			logger.LogInfo("Using network interface: %s", cfgData.NetworkInterface)
		}
		if cfgData.ProxyEnabled {
			logger.LogInfo("Using proxy: %s", cfgData.ProxyURL)
		}
	}

	// Créer le validator pour la validation d'intégrité
	validator := integrity.NewValidator()
	if cfgData.IntegrityCheckEnabled {
		logger.LogInfo("Integrity checking enabled")
	}

	// Créer l'analytics pour les statistiques avancées
	statsFile := filepath.Join(filepath.Dir(cfgData.LogPath), "analytics.json")
	analytics := stats.NewAnalytics(statsFile)

	// Créer l'optimizer pour l'optimisation du stockage
	optimizer := storage.NewOptimizer(cfg, logger)
	if cfgData.StorageDeduplicationEnabled {
		logger.LogInfo("Storage deduplication enabled")
	}

	return &Syncer{
		config:        cfg,
		logger:        logger,
		gpgManager:    gpgManager,
		mirrorManager: mirrorManager,
		httpClient:    httpClient,
		validator:     validator,
		analytics:     analytics,
		optimizer:     optimizer,
		stats:         &SyncStats{},
		activity:      &SyncActivity{},
		rateLimiter:   utils.NewRateLimiter(bandwidthLimit),
		stopChan:      make(chan struct{}),
		stoppedChan:   make(chan struct{}),
	}
}

// Start démarre la boucle de synchronisation
func (s *Syncer) Start(ctx context.Context) {
	s.logger.LogInfo("Starting Debian repository synchronization service")

	// Démarrer le health check des miroirs
	s.mirrorManager.StartHealthCheck()

	ticker := time.NewTicker(time.Duration(s.config.Get().SyncInterval) * time.Minute)
	defer ticker.Stop()

	// Première synchronisation au démarrage (après 30 secondes)
	go func() {
		time.Sleep(30 * time.Second)
		_ = s.Sync()
	}()

	for {
		select {
		case <-ctx.Done():
			s.logger.LogInfo("Sync service stopped by context")
			close(s.stoppedChan)
			return
		case <-s.stopChan:
			s.logger.LogInfo("Sync service stopped")
			close(s.stoppedChan)
			return
		case <-ticker.C:
			_ = s.Sync()
		}
	}
}

// Stop arrête le service de synchronisation
func (s *Syncer) Stop() {
	close(s.stopChan)
	<-s.stoppedChan
}

// ForceSync triggers an immediate sync, bypassing time restrictions
func (s *Syncer) ForceSync() error {
	return s.doSync(true)
}

// Sync effectue une synchronisation complète
func (s *Syncer) Sync() error {
	return s.doSync(false)
}

// doSync is the internal sync method that performs the actual synchronization
func (s *Syncer) doSync(force bool) error {
	if s.isRunning.Load() {
		s.logger.LogInfo("Sync already in progress, skipping")
		return fmt.Errorf("sync already in progress")
	}

	// Check if cluster replication is running - skip sync to avoid conflicts
	if s.replicationMgr != nil && s.replicationMgr.IsRunning() {
		s.logger.LogInfo("Cluster replication is running, skipping sync to avoid conflicts")
		return fmt.Errorf("cluster replication in progress")
	}

	// Vérifier si on est dans la plage horaire autorisée (skip if forced)
	if !force {
		s.waitForAllowedHours()
	} else {
		s.logger.LogInfo("Forced sync requested, bypassing time restrictions")
	}

	s.isRunning.Store(true)
	s.stopRequested.Store(false) // Reset stop flag at start of new sync
	defer func() {
		s.isRunning.Store(false)
		s.stopRequested.Store(false) // Clear stop flag when sync ends
	}()

	cfg := s.config.Get()

	// Log des paramètres de téléchargement
	if cfg.MaxConcurrentDownloads > 1 {
		s.logger.LogInfo("Parallel downloads enabled: %d concurrent downloads", cfg.MaxConcurrentDownloads)
	}
	if cfg.DownloadBandwidthLimit > 0 {
		s.logger.LogInfo("Bandwidth limit: %d KB/s", cfg.DownloadBandwidthLimit)
	}

	// Vérifier l'espace disque avant de commencer
	exceeded, diskInfo, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
	if err != nil {
		s.logger.LogError("Failed to check disk space: %v", err)
		return err
	}

	if exceeded {
		s.logger.LogError("Disk usage (%.2f%%) exceeds maximum allowed (%d%%), aborting sync",
			diskInfo.UsedPercent, cfg.MaxDiskUsagePercent)
		s.stats.mu.Lock()
		s.stats.LastError = fmt.Sprintf("Disk space exceeded: %.2f%%", diskInfo.UsedPercent)
		s.stats.DiskError = true
		s.stats.DiskErrorMessage = fmt.Sprintf("Disk usage (%.2f%%) exceeds maximum allowed (%d%%)", diskInfo.UsedPercent, cfg.MaxDiskUsagePercent)
		s.stats.mu.Unlock()
		return fmt.Errorf("disk space exceeded")
	}

	s.logger.LogInfo("Starting repository sync - Disk usage: %.2f%%", diskInfo.UsedPercent)

	startTime := time.Now()
	s.stats.mu.Lock()
	s.stats.LastSyncStart = startTime
	s.stats.IsRunning = true
	s.stats.LastError = ""
	s.stats.FailedFiles = 0
	s.stats.FailedFilesList = nil // Clear previous failed files
	s.stats.DiskError = false     // Clear disk error on successful sync start
	s.stats.DiskErrorMessage = ""
	s.stats.mu.Unlock()

	// Créer le répertoire du dépôt si nécessaire
	if err := os.MkdirAll(cfg.RepositoryPath, 0755); err != nil {
		s.logger.LogError("Failed to create repository directory: %v", err)
		return err
	}

	var syncError error
	var syncStopped bool

	// Synchroniser d'abord les fichiers Release pour permettre la validation d'intégrité
	s.setActivity("syncing", "Release metadata", "", "", 0, 0)
	s.syncMetadata()

	// Check for stop request after metadata sync
	if s.shouldStop() {
		s.logger.LogInfo("Sync stopped by user request after metadata sync")
		syncStopped = true
		syncError = fmt.Errorf("sync stopped by user request")
		goto syncEnd
	}

	// Synchroniser chaque release
	for _, release := range cfg.DebianReleases {
		// Get release-specific configuration
		releaseConfig := s.config.GetReleaseConfig(release)

		// Determine components to sync for this release
		components := cfg.DebianComponents
		if len(releaseConfig.Components) > 0 {
			components = releaseConfig.Components
		}

		for _, component := range components {
			// Sync translations for this component (shared across architectures)
			if cfg.SyncTranslations {
				s.setActivity("syncing", fmt.Sprintf("Translations: %s/%s", release, component), release, component, 0, 0)
				if err := s.syncSuiteTranslations(cfg.DebianMirror, release, component); err != nil {
					s.logger.LogError("Failed to sync translations for %s/%s: %v", release, component, err)
				}
			}

			for _, arch := range cfg.DebianArchs {
				// Check for stop request before each architecture
				if s.shouldStop() {
					s.logger.LogInfo("Sync stopped by user request during %s/%s", release, component)
					syncStopped = true
					syncError = fmt.Errorf("sync stopped by user request")
					break
				}

				s.setActivity("syncing", fmt.Sprintf("Indexes: %s/%s/%s", release, component, arch), release, component, 0, 0)
				if err := s.syncReleaseComponent(release, component, arch); err != nil {
					s.logger.LogError("Failed to sync %s/%s/%s: %v", release, component, arch, err)
					syncError = err
					atomic.AddInt64(&s.stats.FailedFiles, 1)
					s.recordFailedFile("", "", err.Error(), release, component)
				}

				// Télécharger les packages .deb si activé
				if cfg.SyncPackages {
					// Check for stop request before package download
					if s.shouldStop() {
						s.logger.LogInfo("Sync stopped by user request before package download for %s/%s/%s", release, component, arch)
						syncStopped = true
						syncError = fmt.Errorf("sync stopped by user request")
						break
					}

					s.setActivity("downloading", fmt.Sprintf("Packages: %s/%s/%s", release, component, arch), release, component, 0, 0)
					if err := s.syncPackages(release, component, arch); err != nil {
						s.logger.LogError("Failed to sync packages for %s/%s/%s: %v", release, component, arch, err)
						syncError = err
					}
				}

				// Vérifier l'espace disque à chaque itération
				exceeded, diskInfoCheck, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
				if err != nil {
					s.logger.LogError("Failed to check disk space: %v", err)
					continue
				}
				if exceeded {
					s.logger.LogError("Disk space limit reached during sync, stopping")
					s.stats.mu.Lock()
					s.stats.DiskError = true
					s.stats.DiskErrorMessage = fmt.Sprintf("Disk usage (%.2f%%) exceeds maximum allowed (%d%%)", diskInfoCheck.UsedPercent, cfg.MaxDiskUsagePercent)
					s.stats.mu.Unlock()
					syncError = fmt.Errorf("disk space exceeded during sync")
					break
				}
			}
			if syncStopped {
				break
			}
		}
		if syncStopped {
			break
		}

		// Sync additional suites for this release (-updates, -backports, security)
		if err := s.syncAdditionalSuites(release, releaseConfig, components); err != nil {
			s.logger.LogError("Failed to sync additional suites for %s: %v", release, err)
			syncError = err
		}
	}

	// Check for stop before additional sync tasks
	if syncStopped {
		goto syncEnd
	}

	// Synchroniser les fichiers Contents si activé (pour la recherche de packages)
	if cfg.SyncContents && cfg.PackageSearchEnabled && !s.shouldStop() {
		s.syncContentsFiles()
	}

	// Indexer les packages pour la recherche si activé
	if cfg.PackageSearchEnabled && s.searchDB != nil && !s.shouldStop() {
		s.indexPackagesForSearch()
	}

	// Synchroniser les composants debian-installer si activé (pour build-simple-cdd, netboot, etc.)
	if cfg.SyncDebianInstaller && !s.shouldStop() {
		s.syncDebianInstaller()
	}

	// Synchroniser les dépôts Artica si activé
	if cfg.SyncArticaRepository && !s.shouldStop() {
		s.syncArticaRepository()
		s.SyncArticaCores()
	}

	// Synchroniser les dépôts Ubuntu si activé
	if cfg.SyncUbuntuRepository && len(cfg.UbuntuReleases) > 0 && !s.shouldStop() {
		s.syncUbuntuRepository()
	}

	// Check if we were stopped during additional tasks
	if s.shouldStop() {
		s.logger.LogInfo("Sync stopped by user request during additional tasks")
		syncStopped = true
		syncError = fmt.Errorf("sync stopped by user request")
	}

	// Signer tous les fichiers Release avec GPG si activé (always sign what we have, even if stopped)
	if s.gpgManager != nil && s.gpgManager.IsEnabled() && syncError == nil {
		s.logger.LogInfo("Signing all Release files with GPG...")
		if err := s.gpgManager.SignAllReleaseFiles(); err != nil {
			s.logger.LogError("Failed to sign Release files: %v", err)
			// Ne pas faire échouer toute la sync pour une erreur de signature
		} else {
			s.logger.LogInfo("All Release files signed successfully")
		}
	}

syncEnd:
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Clear activity when sync is done
	s.clearActivity()

	s.stats.mu.Lock()
	s.stats.LastSyncEnd = endTime
	s.stats.LastSyncDuration = duration.String()
	s.stats.IsRunning = false
	if syncError != nil {
		s.stats.LastError = syncError.Error()
	}
	s.stats.mu.Unlock()

	// Marquer la première synchronisation comme terminée
	// Les futures mises à jour seront enregistrées dans la base de données
	if s.updatesDB != nil && s.updatesDB.IsFirstSync() {
		s.updatesDB.MarkFirstSyncComplete()
		s.logger.LogInfo("First sync completed - future package updates will be recorded to database")
	}

	// Run CVE scan after sync if enabled
	if s.cveScanner != nil && s.cveScanner.ShouldScanAfterSync() {
		s.logger.LogInfo("Running CVE scan after sync...")
		go func() {
			if _, err := s.cveScanner.Scan("", "", "", false); err != nil {
				s.logger.LogError("CVE scan after sync failed: %v", err)
			} else {
				s.logger.LogInfo("CVE scan after sync completed")
			}
		}()
	}

	// Trigger cluster replication after sync if enabled
	if s.replicationMgr != nil && cfg.ClusterEnabled && cfg.ClusterAutoReplicate {
		s.logger.LogInfo("Starting cluster replication after sync...")
		go func() {
			if err := s.replicationMgr.ReplicateToPeers(); err != nil {
				s.logger.LogError("Cluster replication after sync failed: %v", err)
			} else {
				s.logger.LogInfo("Cluster replication after sync completed")
			}
		}()
	}

	if syncStopped {
		s.logger.LogInfo("Sync stopped by user after %s", duration)
	} else {
		s.logger.LogInfo("Sync completed in %s", duration)
	}

	// Record sync events to the events database
	s.recordSyncEvents(duration)

	return syncError
}

// recordSyncEvents records sync events to the events database for each repository
func (s *Syncer) recordSyncEvents(duration time.Duration) {
	if s.eventsDB == nil {
		return
	}

	cfg := s.config.Get()
	durationMs := duration.Milliseconds()
	totalFiles := atomic.LoadInt64(&s.stats.TotalFiles)
	totalBytes := atomic.LoadInt64(&s.stats.TotalBytes)
	failedFiles := atomic.LoadInt64(&s.stats.FailedFiles)

	// Record event for each Debian release that was synced
	if len(cfg.DebianReleases) > 0 {
		for _, release := range cfg.DebianReleases {
			// We record the total stats for the main debian sync
			// In a more granular implementation, we could track per-release stats
			if err := s.eventsDB.RecordSyncEvent(totalFiles, totalBytes, "debian/"+release, durationMs, failedFiles); err != nil {
				s.logger.LogError("Failed to record sync event for debian/%s: %v", release, err)
			} else {
				s.logger.LogSync("Recorded sync event for debian/%s", release)
			}
		}
	}

	// Record event for each Ubuntu release that was synced
	if cfg.SyncUbuntuRepository && len(cfg.UbuntuReleases) > 0 {
		for _, release := range cfg.UbuntuReleases {
			if err := s.eventsDB.RecordSyncEvent(totalFiles, totalBytes, "ubuntu/"+release, durationMs, failedFiles); err != nil {
				s.logger.LogError("Failed to record sync event for ubuntu/%s: %v", release, err)
			} else {
				s.logger.LogSync("Recorded sync event for ubuntu/%s", release)
			}
		}
	}

	// Record event for Artica if synced
	if cfg.SyncArticaRepository {
		if err := s.eventsDB.RecordSyncEvent(totalFiles, totalBytes, "artica", durationMs, failedFiles); err != nil {
			s.logger.LogError("Failed to record sync event for artica: %v", err)
		} else {
			s.logger.LogSync("Recorded sync event for artica")
		}
	}

	// Cleanup old events (run asynchronously to not block)
	go func() {
		if deleted, err := s.eventsDB.CleanupOldEvents(15); err != nil {
			s.logger.LogError("Failed to cleanup old events: %v", err)
		} else if deleted > 0 {
			s.logger.LogInfo("Cleaned up %d old sync events (>15 days)", deleted)
		}
	}()
}

// syncReleaseComponent synchronise un composant spécifique d'une release
func (s *Syncer) syncReleaseComponent(release, component, arch string) error {
	cfg := s.config.Get()

	// Get release-specific configuration
	releaseConfig := s.config.GetReleaseConfig(release)

	// Check if this component is available for this release
	if len(releaseConfig.Components) > 0 {
		componentAvailable := false
		for _, c := range releaseConfig.Components {
			if c == component {
				componentAvailable = true
				break
			}
		}
		if !componentAvailable {
			s.logger.LogInfo("Component %s not available for archived release %s, skipping", component, release)
			return nil
		}
	}

	// Use release-specific mirror URL if configured, otherwise use MirrorManager
	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = s.mirrorManager.GetCurrentMirror()
	}
	if mirrorURL == "" {
		return fmt.Errorf("no mirror available")
	}

	// Construire les chemins
	remoteBase := fmt.Sprintf("%s/dists/%s/%s", mirrorURL, release, component)
	localBase := filepath.Join(cfg.RepositoryPath, "dists", release, component)

	// Créer les répertoires locaux
	if err := os.MkdirAll(localBase, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Télécharger les fichiers Packages
	targets := []string{
		fmt.Sprintf("binary-%s/Packages.gz", arch),
		fmt.Sprintf("binary-%s/Packages.xz", arch),
		fmt.Sprintf("binary-%s/Release", arch),
	}

	// Créer les jobs de téléchargement avec les infos de validation
	var jobs []DownloadJob
	for _, target := range targets {
		// Chemin relatif pour la validation (par rapport à dists/<release>/)
		relativePath := fmt.Sprintf("%s/%s", component, target)
		jobs = append(jobs, DownloadJob{
			URL:          fmt.Sprintf("%s/%s", remoteBase, target),
			LocalPath:    filepath.Join(localBase, target),
			ReleaseName:  release,
			RelativePath: relativePath,
		})
	}

	// Télécharger en parallèle
	results := s.downloadFilesParallel(jobs)

	// Traiter les résultats
	successCount := 0
	hasError := false
	var lastError error
	for _, result := range results {
		if result.Error != nil {
			s.logger.LogError("Failed to download %s: %v", result.Job.URL, result.Error)
			atomic.AddInt64(&s.stats.FailedFiles, 1)
			s.recordFailedFile(result.Job.URL, result.Job.LocalPath, result.Error.Error(), release, component)
			hasError = true
			lastError = result.Error
		} else {
			s.logger.LogSync("Downloaded: %s/%s/%s", release, component, arch)
			atomic.AddInt64(&s.stats.TotalFiles, 1)
			successCount++
		}
	}

	// Gestion du failover
	if successCount == 0 {
		// Tous les téléchargements ont échoué, marquer le miroir comme défaillant
		s.mirrorManager.MarkMirrorFailed(mirrorURL, fmt.Errorf("all downloads failed for %s/%s/%s: %v", release, component, arch, lastError))
		return fmt.Errorf("all downloads failed for %s/%s/%s", release, component, arch)
	} else if !hasError {
		// Tous les téléchargements ont réussi, marquer le miroir comme sain
		s.mirrorManager.MarkMirrorSuccess(mirrorURL)
	}

	return nil
}

// syncAdditionalSuites syncs -updates, -backports, and security suites for a release
func (s *Syncer) syncAdditionalSuites(release string, releaseConfig config.ReleaseConfig, components []string) error {
	cfg := s.config.Get()
	var syncError error

	// Sync -updates suite if enabled
	if releaseConfig.SyncUpdates {
		updatesSuite := release + "-updates"
		s.logger.LogInfo("Syncing updates suite: %s", updatesSuite)
		if err := s.syncSuite(releaseConfig.Mirror, updatesSuite, components, cfg.DebianArchs); err != nil {
			s.logger.LogError("Failed to sync updates for %s: %v", release, err)
			syncError = err
		}
	}

	// Sync -backports suite if enabled
	if releaseConfig.SyncBackports {
		backportsSuite := release + "-backports"
		s.logger.LogInfo("Syncing backports suite: %s", backportsSuite)
		if err := s.syncSuite(releaseConfig.Mirror, backportsSuite, components, cfg.DebianArchs); err != nil {
			s.logger.LogError("Failed to sync backports for %s: %v", release, err)
			syncError = err
		}
	}

	// Sync security suite if enabled
	if releaseConfig.SyncSecurity {
		securityMirror := releaseConfig.SecurityMirror
		securitySuite := releaseConfig.SecuritySuite

		if securityMirror != "" && securitySuite != "" {
			s.logger.LogInfo("Syncing security suite: %s from %s", securitySuite, securityMirror)
			if err := s.syncSecuritySuite(securityMirror, securitySuite, components, cfg.DebianArchs); err != nil {
				s.logger.LogError("Failed to sync security for %s: %v", release, err)
				syncError = err
			}
		}
	}

	return syncError
}

// syncSuite syncs a specific suite (e.g., bookworm-updates, bookworm-backports)
func (s *Syncer) syncSuite(mirrorURL, suite string, components, architectures []string) error {
	cfg := s.config.Get()

	if mirrorURL == "" {
		mirrorURL = s.mirrorManager.GetCurrentMirror()
	}
	if mirrorURL == "" {
		return fmt.Errorf("no mirror available")
	}

	// Sync metadata for this suite
	if err := s.syncSuiteMetadata(mirrorURL, suite); err != nil {
		s.logger.LogError("Failed to sync metadata for suite %s: %v", suite, err)
	}

	// Sync each component/architecture
	for _, component := range components {
		// Sync translations for this component (shared across architectures)
		if cfg.SyncTranslations {
			if err := s.syncSuiteTranslations(mirrorURL, suite, component); err != nil {
				s.logger.LogError("Failed to sync translations for %s/%s: %v", suite, component, err)
			}
		}

		for _, arch := range architectures {
			if err := s.syncSuiteComponent(mirrorURL, suite, component, arch); err != nil {
				s.logger.LogError("Failed to sync %s/%s/%s: %v", suite, component, arch, err)
				continue
			}

			// Download packages if enabled
			if cfg.SyncPackages {
				if err := s.syncSuitePackages(mirrorURL, suite, component, arch); err != nil {
					s.logger.LogError("Failed to sync packages for %s/%s/%s: %v", suite, component, arch, err)
				}
			}
		}
	}

	return nil
}

// syncSecuritySuite syncs security updates from a separate mirror
// For archived releases like buster, security is at debian-security with path like "buster/updates"
// For current releases, security is at debian-security with path like "bookworm-security"
func (s *Syncer) syncSecuritySuite(securityMirror, securitySuite string, components, architectures []string) error {
	cfg := s.config.Get()

	// Sync metadata for security suite
	if err := s.syncSuiteMetadata(securityMirror, securitySuite); err != nil {
		s.logger.LogError("Failed to sync security metadata for %s: %v", securitySuite, err)
	}

	// Sync each component/architecture
	for _, component := range components {
		// Sync translations for this component (shared across architectures)
		if cfg.SyncTranslations {
			if err := s.syncSuiteTranslations(securityMirror, securitySuite, component); err != nil {
				s.logger.LogError("Failed to sync security translations for %s/%s: %v", securitySuite, component, err)
			}
		}

		for _, arch := range architectures {
			if err := s.syncSuiteComponent(securityMirror, securitySuite, component, arch); err != nil {
				s.logger.LogError("Failed to sync security %s/%s/%s: %v", securitySuite, component, arch, err)
				continue
			}

			// Download packages if enabled
			if cfg.SyncPackages {
				if err := s.syncSuitePackages(securityMirror, securitySuite, component, arch); err != nil {
					s.logger.LogError("Failed to sync security packages for %s/%s/%s: %v", securitySuite, component, arch, err)
				}
			}
		}
	}

	return nil
}

// syncSuiteMetadata downloads Release, Release.gpg, InRelease files for a suite
func (s *Syncer) syncSuiteMetadata(mirrorURL, suite string) error {
	cfg := s.config.Get()

	remoteBase := fmt.Sprintf("%s/dists/%s", mirrorURL, suite)
	localBase := filepath.Join(cfg.RepositoryPath, "dists", suite)

	if err := os.MkdirAll(localBase, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", localBase, err)
	}

	metadataFiles := []string{"Release", "Release.gpg", "InRelease"}
	for _, file := range metadataFiles {
		remoteURL := fmt.Sprintf("%s/%s", remoteBase, file)
		localPath := filepath.Join(localBase, file)

		if err := s.downloadFileResume(remoteURL, localPath); err != nil {
			// Some files may not exist (e.g., Release.gpg for some suites)
			if file != "Release.gpg" {
				s.logger.LogError("Failed to download %s/%s: %v", suite, file, err)
			}
			continue
		}
		s.logger.LogSync("Downloaded metadata: %s/%s", suite, file)
	}

	return nil
}

// syncSuiteComponent downloads Packages index files for a suite component
func (s *Syncer) syncSuiteComponent(mirrorURL, suite, component, arch string) error {
	cfg := s.config.Get()

	remoteBase := fmt.Sprintf("%s/dists/%s/%s", mirrorURL, suite, component)
	localBase := filepath.Join(cfg.RepositoryPath, "dists", suite, component)

	// Create directory for binary-<arch>
	binaryDir := filepath.Join(localBase, fmt.Sprintf("binary-%s", arch))
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	successCount := 0

	// Download Packages.gz with .xz fallback (generates .gz from .xz if needed)
	packagesGzTarget := fmt.Sprintf("binary-%s/Packages.gz", arch)
	if err := s.downloadIndexFileWithXzFallback(remoteBase, localBase, packagesGzTarget); err == nil {
		s.logger.LogSync("Downloaded: %s/%s/%s", suite, component, packagesGzTarget)
		successCount++
	}

	// Also try to download Packages.xz directly (some clients prefer it)
	packagesXzTarget := fmt.Sprintf("binary-%s/Packages.xz", arch)
	remoteURL := fmt.Sprintf("%s/%s", remoteBase, packagesXzTarget)
	localPath := filepath.Join(localBase, packagesXzTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded: %s/%s/%s", suite, component, packagesXzTarget)
		successCount++
	}

	// Download Release file (optional)
	releaseTarget := fmt.Sprintf("binary-%s/Release", arch)
	remoteURL = fmt.Sprintf("%s/%s", remoteBase, releaseTarget)
	localPath = filepath.Join(localBase, releaseTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded: %s/%s/%s", suite, component, releaseTarget)
	}

	// We need at least one Packages file (.gz or .xz)
	if successCount == 0 {
		return fmt.Errorf("failed to download any index files for %s/%s/%s", suite, component, arch)
	}

	// Ensure .gz file exists (generate from .xz if missing)
	s.ensureGzFilesFromXz(binaryDir)

	return nil
}

// syncSuiteTranslations downloads Translation files (i18n) for a suite component
func (s *Syncer) syncSuiteTranslations(mirrorURL, suite, component string) error {
	cfg := s.config.Get()

	// Check if translations are enabled
	if !cfg.SyncTranslations || len(cfg.TranslationLanguages) == 0 {
		return nil
	}

	remoteBase := fmt.Sprintf("%s/dists/%s/%s/i18n", mirrorURL, suite, component)
	localBase := filepath.Join(cfg.RepositoryPath, "dists", suite, component, "i18n")

	// Create i18n directory
	if err := os.MkdirAll(localBase, 0755); err != nil {
		return fmt.Errorf("failed to create i18n directory: %w", err)
	}

	// Download Translation files for each configured language
	downloadedCount := 0
	for _, lang := range cfg.TranslationLanguages {
		// Try different compression formats - prefer xz, then bz2, then gz, then uncompressed
		formats := []string{
			fmt.Sprintf("Translation-%s.xz", lang),
			fmt.Sprintf("Translation-%s.bz2", lang),
			fmt.Sprintf("Translation-%s.gz", lang),
			fmt.Sprintf("Translation-%s", lang),
		}

		downloaded := false
		for _, filename := range formats {
			remoteURL := fmt.Sprintf("%s/%s", remoteBase, filename)
			localPath := filepath.Join(localBase, filename)

			if err := s.downloadFileResume(remoteURL, localPath); err == nil {
				s.logger.LogSync("Downloaded: %s/%s/i18n/%s", suite, component, filename)
				downloadedCount++
				downloaded = true
				break // Only need one format per language
			}
		}

		if !downloaded {
			// Not all languages exist for all components, this is normal
			s.logger.LogSync("Translation-%s not available for %s/%s (skipped)", lang, suite, component)
		}
	}

	if downloadedCount > 0 {
		s.logger.LogSync("Downloaded %d translation files for %s/%s", downloadedCount, suite, component)
	}

	return nil
}

// syncSuitePackages downloads .deb packages for a suite based on its Packages index
func (s *Syncer) syncSuitePackages(mirrorURL, suite, component, arch string) error {
	cfg := s.config.Get()

	// Find Packages file - prefer .xz as it's more commonly available now
	// Check that file exists AND has content (size > 0)
	packagesPath := ""
	xzPath := filepath.Join(cfg.RepositoryPath, "dists", suite, component, fmt.Sprintf("binary-%s", arch), "Packages.xz")
	gzPath := filepath.Join(cfg.RepositoryPath, "dists", suite, component, fmt.Sprintf("binary-%s", arch), "Packages.gz")

	if stat, err := os.Stat(xzPath); err == nil && stat.Size() > 0 {
		packagesPath = xzPath
	} else if stat, err := os.Stat(gzPath); err == nil && stat.Size() > 0 {
		packagesPath = gzPath
	}

	if packagesPath == "" {
		s.logger.LogInfo("No valid Packages file found for %s/%s/%s, skipping package sync", suite, component, arch)
		return nil
	}

	// Parse Packages file
	packages, err := s.parsePackagesFile(packagesPath)
	if err != nil {
		return fmt.Errorf("failed to parse Packages file: %w", err)
	}

	if len(packages) == 0 {
		s.logger.LogInfo("No packages found in %s/%s/%s", suite, component, arch)
		return nil
	}

	s.logger.LogInfo("Found %d packages in %s/%s/%s", len(packages), suite, component, arch)

	// Create download jobs
	var jobs []DownloadJob
	for _, pkg := range packages {
		localPath := filepath.Join(cfg.RepositoryPath, pkg.Filename)

		// Check if file already exists with correct size
		if stat, err := os.Stat(localPath); err == nil {
			if stat.Size() == pkg.Size {
				continue
			}
		}

		jobs = append(jobs, DownloadJob{
			URL:                fmt.Sprintf("%s/%s", mirrorURL, pkg.Filename),
			LocalPath:          localPath,
			ReleaseName:        suite,
			RelativePath:       pkg.Filename,
			PackageName:        pkg.Package,
			PackageVersion:     pkg.Version,
			PackageDescription: pkg.Description,
			PackageSize:        pkg.Size,
			Component:          component,
			Architecture:       arch,
		})
	}

	if len(jobs) == 0 {
		s.logger.LogInfo("All packages up to date for %s/%s/%s", suite, component, arch)
		return nil
	}

	s.logger.LogInfo("Downloading %d packages for %s/%s/%s", len(jobs), suite, component, arch)

	// Download in batches
	batchSize := 100
	for i := 0; i < len(jobs); i += batchSize {
		end := i + batchSize
		if end > len(jobs) {
			end = len(jobs)
		}

		batch := jobs[i:end]
		results := s.downloadFilesParallel(batch)

		for _, result := range results {
			if result.Error != nil {
				s.logger.LogError("Failed to download %s: %v", result.Job.URL, result.Error)
				atomic.AddInt64(&s.stats.FailedFiles, 1)
			} else {
				atomic.AddInt64(&s.stats.TotalFiles, 1)
			}
		}

		// Check disk space
		exceeded, _, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
		if err != nil {
			s.logger.LogError("Failed to check disk space: %v", err)
		}
		if exceeded {
			s.logger.LogError("Disk space limit reached during suite package sync, stopping")
			return fmt.Errorf("disk space exceeded")
		}
	}

	return nil
}

// syncMetadata synchronise les fichiers de métadonnées Release, InRelease, etc.
func (s *Syncer) syncMetadata() {
	cfg := s.config.Get()

	for _, release := range cfg.DebianReleases {
		// Get release-specific configuration
		releaseConfig := s.config.GetReleaseConfig(release)

		// Use release-specific mirror URL if configured, otherwise use MirrorManager
		mirrorURL := releaseConfig.Mirror
		if mirrorURL == "" {
			mirrorURL = s.mirrorManager.GetCurrentMirror()
		}
		if mirrorURL == "" {
			s.logger.LogError("No mirror available for metadata sync")
			return
		}

		remoteBase := fmt.Sprintf("%s/dists/%s", mirrorURL, release)
		localBase := filepath.Join(cfg.RepositoryPath, "dists", release)

		if err := os.MkdirAll(localBase, 0755); err != nil {
			s.logger.LogError("Failed to create metadata directory: %v", err)
			continue
		}

		metadataFiles := []string{"Release", "Release.gpg", "InRelease"}

		successCount := 0
		errorCount := 0
		var lastError error

		for _, file := range metadataFiles {
			remoteURL := fmt.Sprintf("%s/%s", remoteBase, file)
			localPath := filepath.Join(localBase, file)

			if err := s.downloadFileResume(remoteURL, localPath); err != nil {
				s.logger.LogError("Failed to download metadata %s: %v", file, err)
				errorCount++
				lastError = err
				continue
			}

			s.logger.LogSync("Downloaded metadata: %s/%s", release, file)
			atomic.AddInt64(&s.stats.TotalFiles, 1)
			successCount++
		}

		// Parser le fichier Release pour la validation d'intégrité
		if cfg.IntegrityCheckEnabled {
			releaseFilePath := filepath.Join(localBase, "Release")
			if _, err := os.Stat(releaseFilePath); err == nil {
				if err := s.validator.ParseReleaseFile(release, releaseFilePath); err != nil {
					s.logger.LogError("Failed to parse Release file for %s: %v", release, err)
				} else {
					s.logger.LogInfo("Loaded integrity checksums for release %s", release)
				}
			}
		}

		// Gestion du failover pour les métadonnées
		if successCount == 0 && errorCount > 0 {
			s.mirrorManager.MarkMirrorFailed(mirrorURL, fmt.Errorf("metadata sync failed for %s: %v", release, lastError))
		} else if successCount > 0 && errorCount == 0 {
			s.mirrorManager.MarkMirrorSuccess(mirrorURL)
		}

		// Sync metadata for additional suites (-updates, -backports, security)
		if releaseConfig.SyncUpdates {
			updatesSuite := release + "-updates"
			_ = s.syncSuiteMetadata(mirrorURL, updatesSuite)
		}
		if releaseConfig.SyncBackports {
			backportsSuite := release + "-backports"
			_ = s.syncSuiteMetadata(mirrorURL, backportsSuite)
		}
		if releaseConfig.SyncSecurity && releaseConfig.SecurityMirror != "" && releaseConfig.SecuritySuite != "" {
			_ = s.syncSuiteMetadata(releaseConfig.SecurityMirror, releaseConfig.SecuritySuite)
		}
	}
}

// downloadFileResume télécharge un fichier avec support de reprise et validation d'intégrité
func (s *Syncer) downloadFileResume(url, destPath string) error {
	return s.downloadFileResumeWithValidation(url, destPath, "", "")
}

// downloadFileResumeWithValidation télécharge un fichier avec support de reprise et validation d'intégrité
func (s *Syncer) downloadFileResumeWithValidation(url, destPath, releaseName, relativePath string) error {
	// Créer le répertoire parent si nécessaire
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Vérifier si le fichier existe déjà
	var existingSize int64
	if stat, err := os.Stat(destPath); err == nil {
		existingSize = stat.Size()
	}

	// Créer une requête HTTP avec Range header pour la reprise
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Demander HEAD pour vérifier la taille du fichier distant
	headResp, err := s.httpClient.Head(url)
	if err != nil {
		return fmt.Errorf("failed to check remote file: %w", err)
	}
	headResp.Body.Close()

	// Check HEAD response status code - return error for 404 or other client/server errors
	if headResp.StatusCode >= 400 {
		return fmt.Errorf("bad status: %s", headResp.Status)
	}

	remoteSize := headResp.ContentLength

	// Si le fichier local a la même taille, considérer comme déjà téléchargé
	if existingSize > 0 && existingSize == remoteSize {
		s.logger.LogSync("File already up to date: %s", destPath)
		return nil
	}

	// Si le fichier local est plus petit, reprendre le téléchargement
	var out *os.File
	if existingSize > 0 && existingSize < remoteSize {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existingSize))
		out, err = os.OpenFile(destPath, os.O_WRONLY|os.O_APPEND, 0644)
		s.logger.LogSync("Resuming download from byte %d: %s", existingSize, url)
	} else {
		out, err = os.Create(destPath)
		s.logger.LogSync("Starting download: %s", url)
	}

	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func(out *os.File) {
		_ = out.Close()
	}(out)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// Vérifier le code de statut
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Appliquer le rate limiting si configuré
	cfg := s.config.Get()
	var reader io.Reader = resp.Body
	if cfg.DownloadBandwidthLimit > 0 {
		bandwidthBytes := int64(cfg.DownloadBandwidthLimit) * 1024 // KB/s vers bytes/s
		reader = utils.NewRateLimitedReader(resp.Body, bandwidthBytes)
	}

	// Copier les données avec suivi de progression
	written, err := io.Copy(out, reader)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	atomic.AddInt64(&s.stats.TotalBytes, written)
	s.addSessionDownload(written)

	// Validation d'intégrité si activée et si on a les informations de release
	if cfg.IntegrityCheckEnabled && releaseName != "" && relativePath != "" {
		valid, err := s.validator.ValidateFile(releaseName, relativePath, destPath)
		if err != nil {
			s.logger.LogError("Integrity validation error for %s: %v", destPath, err)
			// On ne fait pas échouer le téléchargement pour une erreur de validation
		} else if !valid {
			s.logger.LogError("Integrity check FAILED for %s", destPath)
			// Supprimer le fichier corrompu
			os.Remove(destPath)
			return fmt.Errorf("integrity check failed for %s", destPath)
		} else {
			s.logger.LogSync("Integrity check passed for %s", destPath)
		}
	}

	return nil
}

// downloadIndexFileWithXzFallback downloads an index file with .gz -> .xz fallback
// If the .gz file returns 404, it tries to download .xz instead and generates .gz from it
func (s *Syncer) downloadIndexFileWithXzFallback(baseURL, localDir, filename string) error {
	// Only apply fallback for .gz files
	if !strings.HasSuffix(filename, ".gz") {
		url := fmt.Sprintf("%s/%s", baseURL, filename)
		localPath := filepath.Join(localDir, filename)
		return s.downloadFileResume(url, localPath)
	}

	// Try .gz first
	gzURL := fmt.Sprintf("%s/%s", baseURL, filename)
	gzPath := filepath.Join(localDir, filename)

	err := s.downloadFileResume(gzURL, gzPath)
	if err == nil {
		return nil // .gz downloaded successfully
	}

	// Check if it's a 404 error
	if !strings.Contains(err.Error(), "404") {
		return err // Different error, don't try fallback
	}

	// Try .xz fallback
	xzFilename := strings.TrimSuffix(filename, ".gz") + ".xz"
	xzURL := fmt.Sprintf("%s/%s", baseURL, xzFilename)
	xzPath := filepath.Join(localDir, xzFilename)

	s.logger.LogSync("Trying .xz fallback for %s (404 on .gz)", filename)

	if err := s.downloadFileResume(xzURL, xzPath); err != nil {
		return fmt.Errorf("both .gz and .xz failed: %w", err)
	}

	// Generate .gz from .xz
	if err := s.generateGzFromXz(xzPath, gzPath); err != nil {
		s.logger.LogError("Failed to generate .gz from .xz: %v", err)
		// Don't fail - we still have the .xz file
		return nil
	}

	s.logger.LogSync("Generated %s from .xz", filename)
	return nil
}

// generateGzFromXz decompresses an .xz file and recompresses to .gz
func (s *Syncer) generateGzFromXz(xzPath, gzPath string) error {
	// Open the .xz file
	xzFile, err := os.Open(xzPath)
	if err != nil {
		return fmt.Errorf("failed to open xz file: %w", err)
	}
	defer xzFile.Close()

	// Create xz reader
	xzReader, err := xz.NewReader(xzFile)
	if err != nil {
		return fmt.Errorf("failed to create xz reader: %w", err)
	}

	// Create the .gz file
	gzFile, err := os.Create(gzPath)
	if err != nil {
		return fmt.Errorf("failed to create gz file: %w", err)
	}
	defer gzFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(gzFile)
	defer gzWriter.Close()

	// Copy decompressed data to gzip writer
	if _, err := io.Copy(gzWriter, xzReader); err != nil {
		os.Remove(gzPath) // Clean up partial file
		return fmt.Errorf("failed to transcode xz to gz: %w", err)
	}

	return nil
}

// ensureGzFilesFromXz scans a directory and generates .gz files from .xz where .gz is missing or empty
func (s *Syncer) ensureGzFilesFromXz(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Recurse into subdirectories
			subDir := filepath.Join(dirPath, entry.Name())
			if err := s.ensureGzFilesFromXz(subDir); err != nil {
				s.logger.LogError("Error processing %s: %v", subDir, err)
			}
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".xz") {
			continue
		}

		// Check if this is a Packages.xz or similar index file
		baseName := strings.TrimSuffix(name, ".xz")
		if baseName != "Packages" && baseName != "Sources" && !strings.HasPrefix(baseName, "Contents-") && !strings.HasPrefix(baseName, "Translation-") {
			continue
		}

		xzPath := filepath.Join(dirPath, name)
		gzPath := filepath.Join(dirPath, baseName+".gz")

		// Check if .gz exists and has content
		gzStat, err := os.Stat(gzPath)
		if err == nil && gzStat.Size() > 0 {
			continue // .gz exists and has content
		}

		// Check if .xz has content
		xzStat, err := os.Stat(xzPath)
		if err != nil || xzStat.Size() == 0 {
			continue // .xz doesn't exist or is empty
		}

		// Generate .gz from .xz
		s.logger.LogSync("Generating %s from %s", baseName+".gz", name)
		if err := s.generateGzFromXz(xzPath, gzPath); err != nil {
			s.logger.LogError("Failed to generate %s: %v", gzPath, err)
		}
	}

	return nil
}

// GetStats retourne les statistiques de synchronisation
func (s *Syncer) GetStats() *SyncStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	// Créer une copie
	stats := &SyncStats{
		TotalFiles:       atomic.LoadInt64(&s.stats.TotalFiles),
		TotalBytes:       atomic.LoadInt64(&s.stats.TotalBytes),
		FailedFiles:      atomic.LoadInt64(&s.stats.FailedFiles),
		LastSyncStart:    s.stats.LastSyncStart,
		LastSyncEnd:      s.stats.LastSyncEnd,
		LastSyncDuration: s.stats.LastSyncDuration,
		IsRunning:        s.isRunning.Load(),
		LastError:        s.stats.LastError,
		DiskError:        s.stats.DiskError,
		DiskErrorMessage: s.stats.DiskErrorMessage,
	}

	// Copy failed files list
	if len(s.stats.FailedFilesList) > 0 {
		stats.FailedFilesList = make([]FailedFile, len(s.stats.FailedFilesList))
		copy(stats.FailedFilesList, s.stats.FailedFilesList)
	}

	return stats
}

// recordFailedFile adds a failed file to the stats
func (s *Syncer) recordFailedFile(url, localPath, errMsg, suite, component string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	// Limit the number of recorded failures to prevent memory issues
	const maxFailedFiles = 1000
	if len(s.stats.FailedFilesList) < maxFailedFiles {
		s.stats.FailedFilesList = append(s.stats.FailedFilesList, FailedFile{
			URL:       url,
			LocalPath: localPath,
			Error:     errMsg,
			Timestamp: time.Now(),
			Suite:     suite,
			Component: component,
		})
	}
}

// GetFailedFiles returns the list of failed files from the last sync
func (s *Syncer) GetFailedFiles() []FailedFile {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	if len(s.stats.FailedFilesList) == 0 {
		return nil
	}

	result := make([]FailedFile, len(s.stats.FailedFilesList))
	copy(result, s.stats.FailedFilesList)
	return result
}

// setActivity updates the current sync activity
func (s *Syncer) setActivity(action, file, suite, component string, filesCount, filesDone int) {
	s.activity.mu.Lock()
	defer s.activity.mu.Unlock()

	s.activity.Action = action
	s.activity.File = file
	s.activity.Suite = suite
	s.activity.Component = component
	s.activity.FilesCount = filesCount
	s.activity.FilesDone = filesDone
	if filesCount > 0 {
		s.activity.Progress = (filesDone * 100) / filesCount
	} else {
		s.activity.Progress = 0
	}
	s.activity.Timestamp = time.Now()
}

// clearActivity clears the current activity when sync is done
func (s *Syncer) clearActivity() {
	s.activity.mu.Lock()
	defer s.activity.mu.Unlock()

	s.activity.Action = ""
	s.activity.File = ""
	s.activity.Suite = ""
	s.activity.Component = ""
	s.activity.Progress = 0
	s.activity.FilesCount = 0
	s.activity.FilesDone = 0
	s.activity.BytesDone = 0
	s.activity.SessionFiles = 0
	s.activity.SessionBytes = 0
}

// addSessionDownload increments session download counters
func (s *Syncer) addSessionDownload(bytes int64) {
	s.activity.mu.Lock()
	defer s.activity.mu.Unlock()
	s.activity.SessionFiles++
	s.activity.SessionBytes += bytes
}

// GetActivity returns a copy of the current sync activity
func (s *Syncer) GetActivity() *SyncActivity {
	s.activity.mu.RLock()
	defer s.activity.mu.RUnlock()

	if !s.isRunning.Load() {
		return nil
	}

	return &SyncActivity{
		Action:       s.activity.Action,
		File:         s.activity.File,
		Suite:        s.activity.Suite,
		Component:    s.activity.Component,
		Progress:     s.activity.Progress,
		BytesDone:    s.activity.BytesDone,
		FilesCount:   s.activity.FilesCount,
		FilesDone:    s.activity.FilesDone,
		SessionFiles: s.activity.SessionFiles,
		SessionBytes: s.activity.SessionBytes,
		Timestamp:    s.activity.Timestamp,
	}
}

// LoadStats charge les statistiques depuis des valeurs persistées
func (s *Syncer) LoadStats(totalFiles, totalBytes, failedFiles int64, lastStart, lastEnd time.Time, lastDuration, lastError string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	atomic.StoreInt64(&s.stats.TotalFiles, totalFiles)
	atomic.StoreInt64(&s.stats.TotalBytes, totalBytes)
	atomic.StoreInt64(&s.stats.FailedFiles, failedFiles)
	s.stats.LastSyncStart = lastStart
	s.stats.LastSyncEnd = lastEnd
	s.stats.LastSyncDuration = lastDuration
	s.stats.LastError = lastError

	s.logger.LogInfo("Loaded persisted sync stats: %d files, %d bytes", totalFiles, totalBytes)
}

// GetMirrorManager retourne le gestionnaire de miroirs
func (s *Syncer) GetMirrorManager() *mirrors.MirrorManager {
	return s.mirrorManager
}

// GetMirrorStats retourne les statistiques des miroirs (wrapper pour l'API)
func (s *Syncer) GetMirrorStats() interface{} {
	if s.mirrorManager == nil {
		return nil
	}
	return s.mirrorManager.GetMirrorStats()
}

// GetAnalytics retourne le module d'analytics
func (s *Syncer) GetAnalytics() *stats.Analytics {
	return s.analytics
}

// GetOptimizer retourne le module d'optimisation du stockage
func (s *Syncer) GetOptimizer() *storage.Optimizer {
	return s.optimizer
}

// GetValidator retourne le module de validation d'intégrité
func (s *Syncer) GetValidator() *integrity.Validator {
	return s.validator
}

// SetUpdatesDB définit la base de données des mises à jour
func (s *Syncer) SetUpdatesDB(db *database.UpdatesDB) {
	s.updatesDB = db
}

// GetUpdatesDB retourne la base de données des mises à jour
func (s *Syncer) GetUpdatesDB() *database.UpdatesDB {
	return s.updatesDB
}

// SetSearchDB définit la base de données de recherche de packages
func (s *Syncer) SetSearchDB(db *database.PackageSearchDB) {
	s.searchDB = db
}

// GetSearchDB retourne la base de données de recherche de packages
func (s *Syncer) GetSearchDB() *database.PackageSearchDB {
	return s.searchDB
}

// SetEventsDB définit la base de données des événements de synchronisation
func (s *Syncer) SetEventsDB(db *database.EventsDB) {
	s.eventsDB = db
}

// GetEventsDB retourne la base de données des événements de synchronisation
func (s *Syncer) GetEventsDB() *database.EventsDB {
	return s.eventsDB
}

// SetPackageIndexer définit le gestionnaire d'index de packages
func (s *Syncer) SetPackageIndexer(indexer PackageIndexer) {
	s.packageIndexer = indexer
}

// SetCVEScanner sets the CVE scanner for the syncer
func (s *Syncer) SetCVEScanner(scanner CVEScannerInterface) {
	s.cveScanner = scanner
}

// SetReplicationManager sets the replication manager for cluster sync
func (s *Syncer) SetReplicationManager(rm ReplicationManagerInterface) {
	s.replicationMgr = rm
}

// CheckForUpdates vérifie si de nouvelles mises à jour sont disponibles
func (s *Syncer) CheckForUpdates() (bool, error) {
	cfg := s.config.Get()

	// Obtenir le miroir actuel
	mirrorURL := s.mirrorManager.GetCurrentMirror()
	if mirrorURL == "" {
		return false, fmt.Errorf("no mirror available")
	}

	for _, release := range cfg.DebianReleases {
		remoteURL := fmt.Sprintf("%s/dists/%s/Release", mirrorURL, release)
		localPath := filepath.Join(cfg.RepositoryPath, "dists", release, "Release")

		// Télécharger le fichier Release distant
		resp, err := s.httpClient.Get(remoteURL)
		if err != nil {
			s.mirrorManager.MarkMirrorFailed(mirrorURL, err)
			return false, fmt.Errorf("failed to fetch remote Release: %w", err)
		}
		defer resp.Body.Close()

		remoteContent, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read remote Release: %w", err)
		}

		// Lire le fichier local s'il existe
		if _, err := os.Stat(localPath); err == nil {
			localContent, err := os.ReadFile(localPath)
			if err != nil {
				return false, fmt.Errorf("failed to read local Release: %w", err)
			}

			// Comparer les contenus
			if string(remoteContent) != string(localContent) {
				s.mirrorManager.MarkMirrorSuccess(mirrorURL)
				return true, nil
			}
		} else {
			// Le fichier local n'existe pas, donc des mises à jour sont disponibles
			s.mirrorManager.MarkMirrorSuccess(mirrorURL)
			return true, nil
		}
	}

	return false, nil
}

// isWithinAllowedHours vérifie si l'heure actuelle est dans la plage horaire autorisée
func (s *Syncer) isWithinAllowedHours() bool {
	cfg := s.config.Get()

	// Si la restriction horaire n'est pas activée, toujours autoriser
	if !cfg.SyncAllowedHoursEnabled {
		return true
	}

	now := time.Now()
	currentTime := now.Format("15:04")

	// Parser les heures de début et de fin
	startTime := cfg.SyncAllowedHoursStart
	endTime := cfg.SyncAllowedHoursEnd

	// Cas simple: start < end (ex: 02:00 - 06:00)
	if startTime < endTime {
		return currentTime >= startTime && currentTime < endTime
	}

	// Cas où la plage traverse minuit (ex: 22:00 - 02:00)
	return currentTime >= startTime || currentTime < endTime
}

// waitForAllowedHours attend que l'heure actuelle soit dans la plage autorisée
func (s *Syncer) waitForAllowedHours() {
	cfg := s.config.Get()

	if !cfg.SyncAllowedHoursEnabled {
		return
	}

	for !s.isWithinAllowedHours() {
		s.logger.LogInfo("Outside allowed sync hours (%s - %s), waiting...",
			cfg.SyncAllowedHoursStart, cfg.SyncAllowedHoursEnd)
		time.Sleep(5 * time.Minute)
	}

	s.logger.LogInfo("Within allowed sync hours (%s - %s), starting sync",
		cfg.SyncAllowedHoursStart, cfg.SyncAllowedHoursEnd)
}

// downloadWorker est un worker pour les téléchargements parallèles
func (s *Syncer) downloadWorker(jobs <-chan DownloadJob, results chan<- DownloadResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		// Check for stop request before each download
		if s.shouldStop() {
			results <- DownloadResult{
				Job:   job,
				Error: fmt.Errorf("sync stopped by user request"),
			}
			continue
		}

		// Extract filename from path for display
		filename := filepath.Base(job.LocalPath)
		s.setActivity("downloading", filename, job.ReleaseName, job.Component, 0, 0)

		err := s.downloadFileResumeWithValidation(job.URL, job.LocalPath, job.ReleaseName, job.RelativePath)
		results <- DownloadResult{
			Job:   job,
			Error: err,
		}
	}
}

// downloadFilesParallel télécharge plusieurs fichiers en parallèle
func (s *Syncer) downloadFilesParallel(jobs []DownloadJob) []DownloadResult {
	cfg := s.config.Get()
	maxWorkers := cfg.MaxConcurrentDownloads
	if maxWorkers <= 0 {
		maxWorkers = 1
	}

	jobsChan := make(chan DownloadJob, len(jobs))
	resultsChan := make(chan DownloadResult, len(jobs))

	// Démarrer les workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go s.downloadWorker(jobsChan, resultsChan, &wg)
	}

	// Envoyer les jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)

	// Attendre la fin des workers
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collecter les résultats
	var results []DownloadResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// IsRunning retourne true si une synchronisation est en cours
func (s *Syncer) IsRunning() bool {
	return s.isRunning.Load()
}

// StopSync requests the current sync to stop gracefully
// Returns true if a sync was running and stop was requested, false otherwise
func (s *Syncer) StopSync() bool {
	if !s.isRunning.Load() {
		return false
	}
	s.stopRequested.Store(true)
	s.logger.LogInfo("Sync stop requested - will stop after current operation completes")
	return true
}

// IsStopping returns true if a sync stop has been requested
func (s *Syncer) IsStopping() bool {
	return s.stopRequested.Load()
}

// shouldStop checks if sync should be stopped (stop requested)
func (s *Syncer) shouldStop() bool {
	return s.stopRequested.Load()
}

// PackageEntry représente une entrée dans le fichier Packages
type PackageEntry struct {
	Package     string
	Version     string
	Description string
	Filename    string
	Size        int64
	MD5sum      string
	SHA256      string
}

// parsePackagesFile parse un fichier Packages (plain, .gz, ou .xz) et retourne la liste des packages
func (s *Syncer) parsePackagesFile(packagesPath string) ([]PackageEntry, error) {
	file, err := os.Open(packagesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Packages file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Détecter le type de compression
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

	var packages []PackageEntry
	var currentPkg PackageEntry

	scanner := bufio.NewScanner(reader)
	// Increase buffer size for long lines (some Description fields are very long)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line = end of package entry
		if line == "" {
			if currentPkg.Filename != "" {
				packages = append(packages, currentPkg)
			}
			currentPkg = PackageEntry{}
			continue
		}

		// Parse key: value
		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Package":
				currentPkg.Package = value
			case "Version":
				currentPkg.Version = value
			case "Description":
				currentPkg.Description = value
			case "Filename":
				currentPkg.Filename = value
			case "Size":
				fmt.Sscanf(value, "%d", &currentPkg.Size)
			case "MD5sum":
				currentPkg.MD5sum = value
			case "SHA256":
				currentPkg.SHA256 = value
			}
		}
	}

	// Don't forget the last package if file doesn't end with empty line
	if currentPkg.Filename != "" {
		packages = append(packages, currentPkg)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Packages file: %w", err)
	}

	return packages, nil
}

// syncPackages télécharge tous les packages .deb d'un composant
func (s *Syncer) syncPackages(release, component, arch string) error {
	cfg := s.config.Get()

	// Chemin vers le fichier Packages.gz local
	packagesPath := filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("binary-%s", arch), "Packages.gz")

	// Vérifier que le fichier existe
	if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
		// Essayer avec .xz
		packagesPath = filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("binary-%s", arch), "Packages.xz")
		if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
			return fmt.Errorf("no Packages file found for %s/%s/%s", release, component, arch)
		}
	}

	// Parser le fichier Packages
	packages, err := s.parsePackagesFile(packagesPath)
	if err != nil {
		return fmt.Errorf("failed to parse Packages file: %w", err)
	}

	s.logger.LogInfo("Found %d packages in %s/%s/%s", len(packages), release, component, arch)

	// Get release-specific configuration
	releaseConfig := s.config.GetReleaseConfig(release)

	// Use release-specific mirror URL if configured, otherwise use MirrorManager
	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = s.mirrorManager.GetCurrentMirror()
	}
	if mirrorURL == "" {
		return fmt.Errorf("no mirror available")
	}

	// Créer les jobs de téléchargement avec les infos du package
	var jobs []DownloadJob
	for _, pkg := range packages {
		localPath := filepath.Join(cfg.RepositoryPath, pkg.Filename)

		// Vérifier si le fichier existe déjà avec la bonne taille
		if stat, err := os.Stat(localPath); err == nil {
			if stat.Size() == pkg.Size {
				// Fichier existe et a la bonne taille, skip
				continue
			}
		}

		jobs = append(jobs, DownloadJob{
			URL:                fmt.Sprintf("%s/%s", mirrorURL, pkg.Filename),
			LocalPath:          localPath,
			ReleaseName:        release,
			RelativePath:       pkg.Filename,
			PackageName:        pkg.Package,
			PackageVersion:     pkg.Version,
			PackageDescription: pkg.Description,
			PackageSize:        pkg.Size,
			Component:          component,
			Architecture:       arch,
		})
	}

	if len(jobs) == 0 {
		s.logger.LogInfo("All packages up to date for %s/%s/%s", release, component, arch)
		return nil
	}

	s.logger.LogInfo("Downloading %d packages for %s/%s/%s", len(jobs), release, component, arch)

	// Télécharger en parallèle par lots pour éviter de surcharger la mémoire
	batchSize := 100
	for i := 0; i < len(jobs); i += batchSize {
		end := i + batchSize
		if end > len(jobs) {
			end = len(jobs)
		}

		batch := jobs[i:end]
		results := s.downloadFilesParallel(batch)

		successCount := 0
		var downloadedPackages []*database.PackageUpdate
		downloadTime := time.Now()

		for _, result := range results {
			if result.Error != nil {
				s.logger.LogError("Failed to download %s: %v", result.Job.URL, result.Error)
				atomic.AddInt64(&s.stats.FailedFiles, 1)
			} else {
				atomic.AddInt64(&s.stats.TotalFiles, 1)
				successCount++

				// Collecter les infos pour la base de données
				if result.Job.PackageName != "" {
					downloadedPackages = append(downloadedPackages, &database.PackageUpdate{
						DownloadedDate:     downloadTime,
						PackageName:        result.Job.PackageName,
						PackageVersion:     result.Job.PackageVersion,
						PackageDescription: result.Job.PackageDescription,
						Release:            result.Job.ReleaseName,
						Component:          result.Job.Component,
						Architecture:       result.Job.Architecture,
						FileSize:           result.Job.PackageSize,
						Filename:           result.Job.RelativePath,
					})
				}
			}
		}

		// Enregistrer les mises à jour dans la base de données
		if s.updatesDB != nil && len(downloadedPackages) > 0 {
			if err := s.updatesDB.RecordUpdates(downloadedPackages); err != nil {
				s.logger.LogError("Failed to record package updates to database: %v", err)
			} else {
				s.logger.LogInfo("Recorded %d package updates to database", len(downloadedPackages))
			}
		}

		s.logger.LogInfo("Downloaded batch %d-%d: %d/%d successful", i+1, end, successCount, len(batch))

		// Vérifier l'espace disque
		exceeded, _, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
		if err != nil {
			s.logger.LogError("Failed to check disk space: %v", err)
		}
		if exceeded {
			s.logger.LogError("Disk space limit reached during package sync, stopping")
			return fmt.Errorf("disk space exceeded during package sync")
		}
	}

	return nil
}

// syncContentsFiles télécharge les fichiers Contents pour la recherche de fichiers
// Les fichiers Contents sont situés dans dists/<release>/<component>/Contents-<arch>.gz
func (s *Syncer) syncContentsFiles() {
	cfg := s.config.Get()
	mirrorURL := s.mirrorManager.GetCurrentMirror()
	if mirrorURL == "" {
		s.logger.LogError("No mirror available for Contents sync")
		return
	}

	s.logger.LogInfo("Syncing Contents files for package search...")

	for _, release := range cfg.DebianReleases {
		for _, component := range cfg.DebianComponents {
			for _, arch := range cfg.DebianArchs {
				// Télécharger Contents-<arch>.gz depuis dists/<release>/<component>/
				contentsFile := fmt.Sprintf("Contents-%s.gz", arch)
				remoteURL := fmt.Sprintf("%s/dists/%s/%s/%s", mirrorURL, release, component, contentsFile)
				localPath := filepath.Join(cfg.RepositoryPath, "dists", release, component, contentsFile)

				// Créer le répertoire si nécessaire
				if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
					s.logger.LogError("Failed to create directory for Contents file: %v", err)
					continue
				}

				if err := s.downloadFileResume(remoteURL, localPath); err != nil {
					// Essayer avec .xz
					contentsFile = fmt.Sprintf("Contents-%s.xz", arch)
					remoteURL = fmt.Sprintf("%s/dists/%s/%s/%s", mirrorURL, release, component, contentsFile)
					localPath = filepath.Join(cfg.RepositoryPath, "dists", release, component, contentsFile)

					if err := s.downloadFileResume(remoteURL, localPath); err != nil {
						s.logger.LogError("Failed to download Contents file for %s/%s/%s: %v", release, component, arch, err)
						continue
					}
				}

				s.logger.LogSync("Downloaded Contents file: %s/%s/%s", release, component, contentsFile)

				// Indexer le fichier Contents si la base de recherche est disponible
				if s.searchDB != nil {
					if err := s.searchDB.IndexContentsFile(localPath, release, component, arch); err != nil {
						s.logger.LogError("Failed to index Contents file for %s/%s/%s: %v", release, component, arch, err)
					} else {
						s.logger.LogInfo("Indexed Contents file for %s/%s/%s", release, component, arch)
					}
				}
			}
		}
	}
}

// indexPackagesForSearch indexe les fichiers Packages pour la recherche
func (s *Syncer) indexPackagesForSearch() {
	if s.searchDB == nil {
		return
	}

	cfg := s.config.Get()
	s.logger.LogInfo("Indexing packages for search...")

	totalIndexed := 0

	for _, release := range cfg.DebianReleases {
		for _, component := range cfg.DebianComponents {
			for _, arch := range cfg.DebianArchs {
				// Trouver le fichier Packages
				packagesPath := filepath.Join(cfg.RepositoryPath, "dists", release, component,
					fmt.Sprintf("binary-%s", arch), "Packages.gz")

				if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
					packagesPath = filepath.Join(cfg.RepositoryPath, "dists", release, component,
						fmt.Sprintf("binary-%s", arch), "Packages.xz")
					if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
						continue
					}
				}

				if err := s.searchDB.IndexPackagesFile(packagesPath, release, component, arch); err != nil {
					s.logger.LogError("Failed to index packages for %s/%s/%s: %v", release, component, arch, err)
				} else {
					totalIndexed++
				}
			}
		}
	}

	s.logger.LogInfo("Package indexing completed: %d component(s) indexed", totalIndexed)
}

// CheckAndEnsureSearchIndexes vérifie si les indexes de recherche existent et les crée si nécessaire
// Cette fonction est appelée au démarrage pour s'assurer que les index sont prêts
func (s *Syncer) CheckAndEnsureSearchIndexes() {
	cfg := s.config.Get()

	// Vérifier si la recherche est activée
	if !cfg.PackageSearchEnabled || s.searchDB == nil {
		return
	}

	s.logger.LogInfo("Checking search indexes status...")

	// Vérifier si les Contents files existent (pour sync_contents)
	// Les fichiers Contents sont dans dists/<release>/<component>/Contents-<arch>.gz
	if cfg.SyncContents {
		needsContentsSync := false
		for _, release := range cfg.DebianReleases {
			for _, component := range cfg.DebianComponents {
				for _, arch := range cfg.DebianArchs {
					contentsPathGz := filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("Contents-%s.gz", arch))
					contentsPathXz := filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("Contents-%s.xz", arch))

					_, errGz := os.Stat(contentsPathGz)
					_, errXz := os.Stat(contentsPathXz)

					if os.IsNotExist(errGz) && os.IsNotExist(errXz) {
						s.logger.LogInfo("Contents file missing for %s/%s/%s, will download", release, component, arch)
						needsContentsSync = true
						break
					}
				}
				if needsContentsSync {
					break
				}
			}
			if needsContentsSync {
				break
			}
		}

		if needsContentsSync {
			s.logger.LogInfo("Downloading missing Contents files...")
			s.syncContentsFiles()
		}
	}

	// Vérifier si les indexes de packages existent dans la base de données
	indexStatus, err := s.searchDB.GetIndexStatus()
	if err != nil {
		s.logger.LogError("Failed to get search index status: %v", err)
		return
	}

	// Créer une map des index existants
	existingIndexes := make(map[string]bool)
	for _, status := range indexStatus {
		key := fmt.Sprintf("%s-%s-%s",
			status["release"],
			status["component"],
			status["architecture"])
		if count, ok := status["packages_count"].(int64); ok && count > 0 {
			existingIndexes[key] = true
		}
	}

	// Vérifier si tous les indexes nécessaires existent
	needsIndexing := false
	for _, release := range cfg.DebianReleases {
		for _, component := range cfg.DebianComponents {
			for _, arch := range cfg.DebianArchs {
				key := fmt.Sprintf("%s-%s-%s", release, component, arch)
				if !existingIndexes[key] {
					// Vérifier si le fichier Packages existe
					packagesPath := filepath.Join(cfg.RepositoryPath, "dists", release, component,
						fmt.Sprintf("binary-%s", arch), "Packages.gz")
					if _, err := os.Stat(packagesPath); err == nil {
						s.logger.LogInfo("Search index missing for %s/%s/%s, will create", release, component, arch)
						needsIndexing = true
						break
					}
				}
			}
			if needsIndexing {
				break
			}
		}
		if needsIndexing {
			break
		}
	}

	if needsIndexing {
		s.logger.LogInfo("Creating missing search indexes...")
		s.indexPackagesForSearch()
	} else {
		s.logger.LogInfo("All search indexes are up to date")
	}
}

// StartSearchIndexChecker démarre un vérificateur périodique des index de recherche
// qui s'assure que les index sont créés si sync_contents est activé
func (s *Syncer) StartSearchIndexChecker(ctx context.Context) {
	cfg := s.config.Get()

	// Si la recherche n'est pas activée, ne rien faire
	if !cfg.PackageSearchEnabled {
		return
	}

	// Vérifier immédiatement au démarrage (après un court délai pour laisser le temps aux autres composants de démarrer)
	go func() {
		time.Sleep(10 * time.Second)
		s.CheckAndEnsureSearchIndexes()
	}()

	// Vérifier périodiquement (toutes les 15 minutes) si la config a changé
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Recharger la config pour voir si sync_contents a été activé
			currentCfg := s.config.Get()
			if currentCfg.PackageSearchEnabled && currentCfg.SyncContents {
				s.CheckAndEnsureSearchIndexes()
			}
			// Vérifier si debian-installer a été activé
			if currentCfg.SyncDebianInstaller {
				s.CheckAndEnsureDebianInstaller()
			}
		}
	}
}

// syncDebianInstaller synchronise les composants debian-installer
// Cela inclut les udebs et les images d'installation (netboot, hd-media, cdrom)
// Nécessaire pour build-simple-cdd, PXE boot, et création d'ISO personnalisés
func (s *Syncer) syncDebianInstaller() {
	cfg := s.config.Get()
	mirrorURL := s.mirrorManager.GetCurrentMirror()
	if mirrorURL == "" {
		s.logger.LogError("No mirror available for debian-installer sync")
		return
	}

	s.logger.LogInfo("Syncing debian-installer components...")

	// Synchroniser les udebs si activé
	if cfg.SyncInstallerUdebs {
		s.syncInstallerUdebs(mirrorURL)
	}

	// Synchroniser les images d'installation si activé
	if cfg.SyncInstallerImages {
		s.syncInstallerImages(mirrorURL)
	}

	s.logger.LogInfo("debian-installer sync completed")
}

// syncInstallerUdebs synchronise les packages udeb (micro-packages pour l'installateur)
// Structure: dists/<release>/<component>/debian-installer/binary-<arch>/
func (s *Syncer) syncInstallerUdebs(mirrorURL string) {
	cfg := s.config.Get()

	s.logger.LogInfo("Syncing debian-installer udebs...")

	for _, release := range cfg.DebianReleases {
		for _, component := range cfg.DebianComponents {
			for _, arch := range cfg.DebianArchs {
				s.syncUdebsForComponent(mirrorURL, release, component, arch)
			}
		}
	}
}

// syncUdebsForComponent synchronise les udebs pour un composant spécifique
func (s *Syncer) syncUdebsForComponent(mirrorURL, release, component, arch string) {
	cfg := s.config.Get()
	basePath := fmt.Sprintf("dists/%s/%s/debian-installer/binary-%s", release, component, arch)
	localBasePath := filepath.Join(cfg.RepositoryPath, basePath)

	// Créer le répertoire local
	if err := os.MkdirAll(localBasePath, 0755); err != nil {
		s.logger.LogError("Failed to create udeb directory %s: %v", localBasePath, err)
		return
	}

	// Liste des fichiers d'index à télécharger
	indexFiles := []string{"Packages", "Packages.gz", "Packages.xz", "Release"}

	for _, indexFile := range indexFiles {
		remoteURL := fmt.Sprintf("%s/%s/%s", mirrorURL, basePath, indexFile)
		localPath := filepath.Join(localBasePath, indexFile)

		if err := s.downloadFileResume(remoteURL, localPath); err != nil {
			// Packages.xz peut ne pas exister, ce n'est pas une erreur critique
			if indexFile != "Packages.xz" && indexFile != "Release" {
				s.logger.LogError("Failed to download udeb index %s/%s/%s: %v", release, component, indexFile, err)
			}
			continue
		}
		s.logger.LogSync("Downloaded udeb index: %s/%s/debian-installer/%s", release, component, indexFile)
	}

	// Télécharger les packages udebs en parsant Packages.gz
	packagesPath := filepath.Join(localBasePath, "Packages.gz")
	if _, err := os.Stat(packagesPath); err == nil {
		s.downloadUdebPackages(mirrorURL, release, component, arch, packagesPath)
	}
}

// downloadUdebPackages télécharge les packages udeb listés dans Packages.gz
func (s *Syncer) downloadUdebPackages(mirrorURL, release, component, arch, packagesPath string) {
	cfg := s.config.Get()

	file, err := os.Open(packagesPath)
	if err != nil {
		s.logger.LogError("Failed to open Packages file: %v", err)
		return
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		s.logger.LogError("Failed to create gzip reader for udebs: %v", err)
		return
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var jobs []DownloadJob
	var currentFilename string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Filename: ") {
			currentFilename = strings.TrimPrefix(line, "Filename: ")
		}

		// Fin d'une entrée de package
		if line == "" && currentFilename != "" {
			localPath := filepath.Join(cfg.RepositoryPath, currentFilename)

			// Vérifier si le fichier existe déjà
			if _, err := os.Stat(localPath); os.IsNotExist(err) {
				jobs = append(jobs, DownloadJob{
					URL:       fmt.Sprintf("%s/%s", mirrorURL, currentFilename),
					LocalPath: localPath,
				})
			}
			currentFilename = ""
		}
	}

	if len(jobs) > 0 {
		s.logger.LogInfo("Downloading %d udeb packages for %s/%s/%s...", len(jobs), release, component, arch)
		s.downloadFilesParallel(jobs)
	}
}

// syncInstallerImages synchronise les images d'installation
// Structure: dists/<release>/<component>/installer-<arch>/current/images/
func (s *Syncer) syncInstallerImages(mirrorURL string) {
	cfg := s.config.Get()

	s.logger.LogInfo("Syncing installer images...")

	for _, release := range cfg.DebianReleases {
		// Les images d'installation sont généralement seulement dans main
		for _, arch := range cfg.DebianArchs {
			s.syncImagesForArch(mirrorURL, release, "main", arch)
		}
	}
}

// syncImagesForArch synchronise les images d'installation pour une architecture
func (s *Syncer) syncImagesForArch(mirrorURL, release, component, arch string) {
	cfg := s.config.Get()
	basePath := fmt.Sprintf("dists/%s/%s/installer-%s/current/images", release, component, arch)
	localBasePath := filepath.Join(cfg.RepositoryPath, basePath)

	// Créer le répertoire de base
	if err := os.MkdirAll(localBasePath, 0755); err != nil {
		s.logger.LogError("Failed to create installer images directory: %v", err)
		return
	}

	// Télécharger les fichiers manifestes
	manifestFiles := []string{"MANIFEST", "MANIFEST.udebs", "MD5SUMS", "SHA256SUMS", "udeb.list"}
	for _, manifest := range manifestFiles {
		remoteURL := fmt.Sprintf("%s/%s/%s", mirrorURL, basePath, manifest)
		localPath := filepath.Join(localBasePath, manifest)

		if err := s.downloadFileResume(remoteURL, localPath); err != nil {
			// Ces fichiers peuvent ne pas tous exister
			continue
		}
		s.logger.LogSync("Downloaded installer manifest: %s/%s", basePath, manifest)
	}

	// Télécharger les types d'images configurés
	for _, imageType := range cfg.InstallerImageTypes {
		s.syncImageType(mirrorURL, release, component, arch, imageType)
	}
}

// syncImageType synchronise un type d'image spécifique (netboot, hd-media, cdrom)
func (s *Syncer) syncImageType(mirrorURL, release, component, arch, imageType string) {
	cfg := s.config.Get()
	basePath := fmt.Sprintf("dists/%s/%s/installer-%s/current/images/%s", release, component, arch, imageType)
	localBasePath := filepath.Join(cfg.RepositoryPath, basePath)

	// Créer le répertoire
	if err := os.MkdirAll(localBasePath, 0755); err != nil {
		s.logger.LogError("Failed to create %s directory: %v", imageType, err)
		return
	}

	s.logger.LogInfo("Syncing %s images for %s/%s...", imageType, release, arch)

	// Télécharger récursivement le contenu du répertoire
	s.syncInstallerDirectory(mirrorURL, basePath, localBasePath)
}

// syncInstallerDirectory synchronise récursivement un répertoire d'images d'installation
func (s *Syncer) syncInstallerDirectory(mirrorURL, remotePath, localPath string) {
	// Télécharger l'index du répertoire pour lister les fichiers
	// On va télécharger les fichiers connus pour chaque type d'image

	cfg := s.config.Get()

	// Fichiers communs à télécharger pour netboot
	if strings.Contains(remotePath, "/netboot") {
		netbootFiles := []string{
			"mini.iso",
			"netboot.tar.gz",
			"pxelinux.0",
			"pxelinux.cfg/default",
			"ldlinux.c32",
			"debian-installer/amd64/initrd.gz",
			"debian-installer/amd64/linux",
			"debian-installer/amd64/pxelinux.0",
			"debian-installer/amd64/pxelinux.cfg/default",
			"debian-installer/amd64/boot-screens/menu.cfg",
			"debian-installer/amd64/boot-screens/stdmenu.cfg",
			"debian-installer/amd64/boot-screens/splash.png",
			"debian-installer/amd64/boot-screens/txt.cfg",
			"debian-installer/amd64/boot-screens/syslinux.cfg",
			"debian-installer/amd64/boot-screens/vesamenu.c32",
			"debian-installer/amd64/boot-screens/ldlinux.c32",
			"debian-installer/amd64/boot-screens/libcom32.c32",
			"debian-installer/amd64/boot-screens/libutil.c32",
			"debian-installer/arm64/initrd.gz",
			"debian-installer/arm64/linux",
			"gtk/mini.iso",
			"gtk/netboot.tar.gz",
			"gtk/debian-installer/amd64/initrd.gz",
			"gtk/debian-installer/amd64/linux",
		}
		s.downloadInstallerFiles(mirrorURL, remotePath, localPath, netbootFiles, cfg.MaxConcurrentDownloads)
	}

	// Fichiers pour hd-media
	if strings.Contains(remotePath, "/hd-media") {
		hdMediaFiles := []string{
			"initrd.gz",
			"vmlinuz",
			"hd-media.tar.gz",
			"gtk/initrd.gz",
			"gtk/vmlinuz",
			"gtk/hd-media.tar.gz",
		}
		s.downloadInstallerFiles(mirrorURL, remotePath, localPath, hdMediaFiles, cfg.MaxConcurrentDownloads)
	}

	// Fichiers pour cdrom
	if strings.Contains(remotePath, "/cdrom") {
		cdromFiles := []string{
			"initrd.gz",
			"vmlinuz",
			"cdrom.tar.gz",
			"gtk/initrd.gz",
			"gtk/vmlinuz",
			"gtk/cdrom.tar.gz",
		}
		s.downloadInstallerFiles(mirrorURL, remotePath, localPath, cdromFiles, cfg.MaxConcurrentDownloads)
	}
}

// downloadInstallerFiles télécharge une liste de fichiers d'installation
func (s *Syncer) downloadInstallerFiles(mirrorURL, remotePath, localPath string, files []string, _ int) {
	var jobs []DownloadJob

	for _, file := range files {
		remoteURL := fmt.Sprintf("%s/%s/%s", mirrorURL, remotePath, file)
		localFilePath := filepath.Join(localPath, file)

		// Créer le répertoire parent si nécessaire
		parentDir := filepath.Dir(localFilePath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			s.logger.LogError("Failed to create directory %s: %v", parentDir, err)
			continue
		}

		// Vérifier si le fichier existe déjà
		if _, err := os.Stat(localFilePath); os.IsNotExist(err) {
			jobs = append(jobs, DownloadJob{
				URL:       remoteURL,
				LocalPath: localFilePath,
			})
		}
	}

	if len(jobs) > 0 {
		s.logger.LogInfo("Downloading %d installer files...", len(jobs))
		s.downloadFilesParallel(jobs)
	}
}

// CheckAndEnsureDebianInstaller vérifie si les fichiers debian-installer existent et les télécharge si nécessaire
func (s *Syncer) CheckAndEnsureDebianInstaller() {
	cfg := s.config.Get()

	if !cfg.SyncDebianInstaller {
		return
	}

	s.logger.LogInfo("Checking debian-installer files...")

	needsSync := false
	mirrorURL := s.mirrorManager.GetCurrentMirror()
	if mirrorURL == "" {
		s.logger.LogError("No mirror available for debian-installer check")
		return
	}

	// Vérifier si les fichiers udeb existent
	if cfg.SyncInstallerUdebs {
		for _, release := range cfg.DebianReleases {
			for _, component := range cfg.DebianComponents {
				for _, arch := range cfg.DebianArchs {
					packagesPath := filepath.Join(cfg.RepositoryPath, "dists", release, component,
						"debian-installer", fmt.Sprintf("binary-%s", arch), "Packages.gz")
					if _, err := os.Stat(packagesPath); os.IsNotExist(err) {
						s.logger.LogInfo("Missing udeb index for %s/%s/%s", release, component, arch)
						needsSync = true
						break
					}
				}
				if needsSync {
					break
				}
			}
			if needsSync {
				break
			}
		}
	}

	// Vérifier si les images d'installation existent
	if cfg.SyncInstallerImages && !needsSync {
		for _, release := range cfg.DebianReleases {
			for _, arch := range cfg.DebianArchs {
				for _, imageType := range cfg.InstallerImageTypes {
					imagePath := filepath.Join(cfg.RepositoryPath, "dists", release, "main",
						fmt.Sprintf("installer-%s", arch), "current", "images", imageType)
					if _, err := os.Stat(imagePath); os.IsNotExist(err) {
						s.logger.LogInfo("Missing installer images for %s/%s/%s", release, arch, imageType)
						needsSync = true
						break
					}
				}
				if needsSync {
					break
				}
			}
			if needsSync {
				break
			}
		}
	}

	if needsSync {
		s.logger.LogInfo("Downloading missing debian-installer files...")
		s.syncDebianInstaller()
	} else {
		s.logger.LogInfo("All debian-installer files are present")
	}
}

func (s *Syncer) SyncArticaMain() (error, articarepos.Repos) {
	s.logger.LogInfo("Syncing Artica main versions...")
	var HttpContent1 = regexp.MustCompile(`<CONTENT>(.+?)</CONTENT>`)
	zUrl := articarepos.ArticaCoreMainVer(s.config)
	s.logger.LogInfo("Downloading %v", zUrl)
	indexContent, err := s.downloadArticaIndex(zUrl)
	if err != nil {
		return fmt.Errorf("%v Failed to download Artica Core index : %v", utils.GetCalleRuntime(), err), articarepos.Repos{}
	}
	if len(indexContent) == 0 {
		return fmt.Errorf("%v Empty Artica Core index received", utils.GetCalleRuntime()), articarepos.Repos{}
	}
	Text := utils.RegexGroup1(HttpContent1, indexContent)
	if len(Text) < 10 {
		return fmt.Errorf("%v Error Corrupted %v", utils.GetCalleRuntime(), Text), articarepos.Repos{}
	}
	err, rep := articarepos.ParseArticaMainVers(Text)
	if err != nil {
		return err, articarepos.Repos{}
	}
	return nil, rep
}
func (s *Syncer) SyncArticaCores() {
	err, Rep := s.SyncArticaMain()
	s.logger.LogInfo("Syncing Artica Cores version...")
	zUrl := articarepos.ArticaCoreUrlIndex(s.config)
	s.logger.LogInfo("Downloading %v", zUrl)
	indexContent, err := s.downloadArticaIndex(zUrl)
	if err != nil {
		s.logger.LogError("%v Failed to download Artica Core index : %v", utils.GetCalleRuntime(), err)
		return
	}

	if len(indexContent) == 0 {
		s.logger.LogError("Empty Artica Core index received")
		return
	}
	Decoded := articarepos.Base64Decode(indexContent)

	if len(Decoded) < 10 {
		s.logger.LogError("%v Error Corrupted %v len<10", utils.GetCalleRuntime(), indexContent)
		return
	}
	IndexDir := s.config.RepositoryPath + "/artica/indexes"
	err = utils.CreateDir(IndexDir)
	if err != nil {
		s.logger.LogError("%v Failed to create indexes directory %s : %v", utils.GetCalleRuntime(), IndexDir, err)
		return
	}
	IndexPath := IndexDir + "/core.json"
	err, Rep = articarepos.ParseArticaCoreServicePacks(Rep, indexContent)
	if err != nil {
		s.logger.LogError("%v Failed to parse Artica Core index : %v", utils.GetCalleRuntime(), err)
		return
	}
	Rep = articarepos.ArticaUrlHotfixes(s.config, Rep)
	for _, THots := range Rep.HotfixesUrls {
		indexContent, err := s.downloadArticaIndex(THots.URL)
		if err != nil {
			s.logger.LogError("%v Failed to download Artica Hotfix index : %v", utils.GetCalleRuntime(), err)
			return
		}

		err, Records := articarepos.ArticaHotfixes(s.config, THots, indexContent)
		if err != nil {
			s.logger.LogError("%v Failed to parse Artica Hotfix dev index : %v", utils.GetCalleRuntime(), err)
			return
		}
		for _, rec := range Records {
			Rep.HotfixesDev = append(Rep.HotfixesDev, rec)
		}
	}

	NewJsonBytes, err := json.MarshalIndent(Rep, "", "\t")
	if err != nil {
		s.logger.LogError("%v Failed to encode to json Artica Core index : %v", utils.GetCalleRuntime(), err)
		return
	}
	err = utils.FilePutContentsBytes(IndexPath, NewJsonBytes)
	if err != nil {
		s.logger.LogError("%v Failed to save Artica Core index %v : %v", utils.GetCalleRuntime(), IndexPath, err)
		return
	}
	for _, Conf := range Rep.OFF {
		var DonwloadConf articarepos.ArticaDownloader
		DonwloadConf.DestinationFile = fmt.Sprintf("%s/artica/%v/%v", s.config.RepositoryPath, Conf.VERSION, Conf.FILENAME)
		DonwloadConf.Size = Conf.FILESIZE
		DonwloadConf.Url = Conf.URL
		DonwloadConf.Md5 = Conf.MD5
		DonwloadConf.TempDir = fmt.Sprintf("%s/artica/tmp", s.config.RepositoryPath)
		err := s.DownloadPackage(DonwloadConf)
		if err != nil {
			s.logger.LogError("%v Failed download Artica Core : %v", utils.GetCalleRuntime(), err)
			return
		}
	}
	for MainVersion, Array1 := range Rep.ServicePacks {
		for _, Conf := range Array1 {
			var DonwloadConf articarepos.ArticaDownloader
			DonwloadConf.DestinationFile = fmt.Sprintf("%s/artica/%v/SP/%v", s.config.RepositoryPath, MainVersion, filepath.Base(Conf.URL))
			DonwloadConf.Size = Conf.FILESIZE
			DonwloadConf.Url = Conf.URL
			DonwloadConf.Md5 = Conf.MD5
			DonwloadConf.TempDir = fmt.Sprintf("%s/artica/tmp", s.config.RepositoryPath)
			err := s.DownloadPackage(DonwloadConf)
			if err != nil {
				s.logger.LogError("%v Failed download Artica Service Pack : %v", utils.GetCalleRuntime(), err)
				return
			}
		}
	}
	for _, Conf := range Rep.HotfixesOfficials {
		var DonwloadConf articarepos.ArticaDownloader
		DonwloadConf.DestinationFile = fmt.Sprintf("%s/artica/%v/SP/%v/hotfix/%v", s.config.RepositoryPath, Conf.ArticaVersion, Conf.ServicePack, filepath.Base(Conf.URL))
		DonwloadConf.Size = utils.StrToInt64(Conf.Size)
		DonwloadConf.Url = Conf.Url
		DonwloadConf.Md5 = Conf.Md5
		DonwloadConf.TempDir = fmt.Sprintf("%s/artica/tmp", s.config.RepositoryPath)
		err := s.DownloadPackage(DonwloadConf)
		if err != nil {
			s.logger.LogError("%v Failed download Artica Official Hotfix : %v", utils.GetCalleRuntime(), err)
			return
		}
	}
	for _, Conf := range Rep.HotfixesDev {
		var DonwloadConf articarepos.ArticaDownloader
		DonwloadConf.DestinationFile = fmt.Sprintf("%s/artica/%v/SP/%v/hotfix-dev/%v", s.config.RepositoryPath, Conf.ArticaVersion, Conf.ServicePack, filepath.Base(Conf.URL))
		DonwloadConf.Size = utils.StrToInt64(Conf.Size)
		DonwloadConf.Url = Conf.Url
		DonwloadConf.Md5 = Conf.Md5
		DonwloadConf.TempDir = fmt.Sprintf("%s/artica/tmp", s.config.RepositoryPath)
		err := s.DownloadPackage(DonwloadConf)
		if err != nil {
			s.logger.LogError("%v Failed download Artica Official Hotfix : %v", utils.GetCalleRuntime(), err)
			return
		}
	}

}
func (s *Syncer) syncArticaRepository() {
	cfg := s.config.Get()

	s.logger.LogInfo("Syncing Artica repositories...")

	// Obtenir les URLs des index Artica pour chaque distribution
	articaURLs := articarepos.GetArticaRepoUrls(s.config)

	// Track which releases need index regeneration
	releasesNeedingUpdate := make(map[string]bool)
	packagesBuilt := 0

	for _, release := range cfg.DebianReleases {
		indexURL, exists := articaURLs[release]
		if !exists {
			s.logger.LogInfo("No Artica repository URL for release %s, skipping", release)
			continue
		}

		s.logger.LogInfo("Syncing Artica repository for %s from %s", release, indexURL)

		// Télécharger le contenu de l'index
		indexContent, err := s.downloadArticaIndex(indexURL)
		if err != nil {
			s.logger.LogError("Failed to download Artica index for %s: %v", release, err)
			continue
		}

		if len(indexContent) == 0 {
			s.logger.LogError("Empty Artica index received for %s", release)
			continue
		}

		// Parser l'index et obtenir la liste des packages
		err, articaRepo := articarepos.ListArticaReposSrc(s.config, release, indexContent)
		if err != nil {
			s.logger.LogError("Failed to parse Artica index for %s: %v", release, err)
			continue
		}

		s.logger.LogInfo("Found %d Artica packages for %s", len(articaRepo.Softs), release)

		// Télécharger chaque package et créer le .deb
		for _, soft := range articaRepo.Softs {
			if err := s.downloadArticaPackage(soft); err != nil {
				s.logger.LogError("Failed to download Artica package %s: %v", soft.ProductCode, err)
				atomic.AddInt64(&s.stats.FailedFiles, 1)
				continue
			}
			s.logger.LogSync("Downloaded Artica package: %s v%s", soft.ProductCode, soft.Version)
			atomic.AddInt64(&s.stats.TotalFiles, 1)

			// Créer le package .deb
			s.logger.LogInfo("Building .deb package for %s...", soft.ProductCode)
			result, err := articarepos.BuildDebPackage(soft)
			if err != nil {
				s.logger.LogError("Failed to build .deb for %s: %v", soft.ProductCode, err)
				continue
			}
			s.logger.LogSync("Built .deb package: %s", result.DebPath)
			s.logger.LogInfo("Extracted content to: %s", result.ExtractPath)

			// Ajouter le package au dépôt Debian mirror
			s.logger.LogInfo("Adding %s to Debian repository...", filepath.Base(result.DebPath))
			if err := articarepos.AddToRepository(result.DebPath, cfg.RepositoryPath, release, "artica", "all"); err != nil {
				s.logger.LogError("Failed to add %s to repository: %v", soft.ProductCode, err)
			} else {
				s.logger.LogSync("Added to repository: pool/artica/a/%s", filepath.Base(result.DebPath))
				releasesNeedingUpdate[release] = true
				packagesBuilt++
			}
		}
	}

	// Régénérer les indexes pour les releases modifiées
	if packagesBuilt > 0 && s.packageIndexer != nil {
		s.logger.LogInfo("Regenerating repository indexes for Artica packages...")

		for release := range releasesNeedingUpdate {
			for _, arch := range cfg.DebianArchs {
				s.logger.LogInfo("Regenerating indexes for %s/artica/%s", release, arch)
				if err := s.packageIndexer.RegenerateIndexes(release, "artica", arch); err != nil {
					s.logger.LogError("Failed to regenerate indexes for %s/artica/%s: %v", release, arch, err)
				} else {
					s.logger.LogSync("Indexes regenerated for %s/artica/%s", release, arch)
				}
			}
			// Also regenerate for "all" architecture
			s.logger.LogInfo("Regenerating indexes for %s/artica/all", release)
			if err := s.packageIndexer.RegenerateIndexes(release, "artica", "all"); err != nil {
				s.logger.LogError("Failed to regenerate indexes for %s/artica/all: %v", release, err)
			}
		}

		s.logger.LogInfo("Repository indexes updated with %d Artica packages", packagesBuilt)
	}

	s.logger.LogInfo("Artica repository sync completed")
}
func (s *Syncer) downloadArticaIndex(indexURL string) (string, error) {
	resp, err := s.httpClient.Get(indexURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Artica index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status fetching Artica index: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Artica index: %w", err)
	}

	return string(content), nil
}
func (s *Syncer) DownloadPackage(Params articarepos.ArticaDownloader) error {

	if _, err := os.Stat(Params.DestinationFile); err == nil {
		valid, err := s.verifyArticaFile(Params.DestinationFile, Params.Md5, Params.Size)
		if err != nil {
			s.logger.LogError("Error verifying existing file %s: %v, will re-download", Params.DestinationFile, err)
		} else if valid {
			return nil
		} else {
			s.logger.LogInfo("Package %s exists but MD5 (%s)/size (%d bytes) mismatch, re-downloading", filepath.Base(Params.Url), Params.Md5, Params.Size)
		}
	}

	if err := os.MkdirAll(Params.TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory %s: %w", Params.TempDir, err)
	}
	TargetDir := filepath.Dir(Params.DestinationFile)
	err := utils.CreateDir(TargetDir)
	if err != nil {
		return fmt.Errorf("failed to create target directory %s: %w", TargetDir, err)
	}
	Tempfile := Params.TempDir + "/" + filepath.Base(Params.Url)

	if _, err := os.Stat(Tempfile); err == nil {
		valid, err := s.verifyArticaFile(Tempfile, Params.Md5, Params.Size)
		if err != nil {
			s.logger.LogError("Error verifying existing file %s: %v, will re-download", Tempfile, err)
		} else if valid {
			s.logger.LogSync("Package %s already up to date (MD5 and size match)", filepath.Base(Params.Url))
			return nil
		} else {
			s.logger.LogInfo("%v Package %s exists but MD5 (%s) /size mismatch, re-downloading", utils.GetCalleRuntime(), filepath.Base(Params.Url), Params.Md5)
		}
	}
	textSize := ""
	if Params.Size > 0 {
		textSize = fmt.Sprintf("(%d bytes)", Params.Size)
	}
	if len(Params.Md5) > 0 {
		textSize = textSize + fmt.Sprintf("MD5: %s", Params.Md5)
	}
	s.logger.LogInfo("%v Downloading package %s %s from %s", utils.GetCalleRuntime(), filepath.Base(Params.Url), textSize, Params.Url)

	resp, err := s.httpClient.Get(Params.Url)
	if err != nil {
		return fmt.Errorf("failed to download package: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status downloading package: %s", resp.Status)
	}
	tmpFile := Tempfile + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	hash := md5.New()
	writer := io.MultiWriter(out, hash)

	cfg := s.config.Get()
	var reader io.Reader = resp.Body
	if cfg.DownloadBandwidthLimit > 0 {
		bandwidthBytes := int64(cfg.DownloadBandwidthLimit) * 1024
		reader = utils.NewRateLimitedReader(resp.Body, bandwidthBytes)
	}

	written, err := io.Copy(writer, reader)
	_ = out.Close()

	if err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to write package file: %w", err)
	}
	if Params.Size > 10 {
		if written != Params.Size {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("size mismatch: expected %d, got %d", Params.Size, written)
		}
	}
	if len(Params.Md5) > 5 {
		downloadedMD5 := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(downloadedMD5, Params.Md5) {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("MD5 mismatch: expected %s, got %s", Params.Md5, downloadedMD5)
		}
	}

	if err := os.Rename(tmpFile, Params.DestinationFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	atomic.AddInt64(&s.stats.TotalBytes, written)
	s.addSessionDownload(written)
	return nil
}
func (s *Syncer) downloadArticaPackage(soft articarepos.ArticaSoft) error {
	if err := os.MkdirAll(soft.TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory %s: %w", soft.TempDir, err)
	}

	if _, err := os.Stat(soft.Tempfile); err == nil {
		valid, err := s.verifyArticaFile(soft.Tempfile, soft.Md5, soft.Size)
		if err != nil {
			s.logger.LogError("Error verifying existing file %s: %v, will re-download", soft.Tempfile, err)
		} else if valid {
			s.logger.LogSync("Package %s already up to date (MD5 and size match)", soft.ProductCode)
			return nil
		} else {
			s.logger.LogInfo("Package %s exists but MD5/size mismatch, re-downloading", soft.ProductCode)
		}
	}
	s.logger.LogInfo("Downloading Artica package %s v%s (%d bytes) from %s", soft.ProductCode, soft.Version, soft.Size, soft.Url)

	resp, err := s.httpClient.Get(soft.Url)
	if err != nil {
		return fmt.Errorf("failed to download package: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status downloading package: %s", resp.Status)
	}
	tmpFile := soft.Tempfile + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	hash := md5.New()
	writer := io.MultiWriter(out, hash)

	cfg := s.config.Get()
	var reader io.Reader = resp.Body
	if cfg.DownloadBandwidthLimit > 0 {
		bandwidthBytes := int64(cfg.DownloadBandwidthLimit) * 1024
		reader = utils.NewRateLimitedReader(resp.Body, bandwidthBytes)
	}

	written, err := io.Copy(writer, reader)
	_ = out.Close()

	if err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to write package file: %w", err)
	}
	if written != soft.Size {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("size mismatch: expected %d, got %d", soft.Size, written)
	}
	downloadedMD5 := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(downloadedMD5, soft.Md5) {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("MD5 mismatch: expected %s, got %s", soft.Md5, downloadedMD5)
	}
	if err := os.Rename(tmpFile, soft.Tempfile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	atomic.AddInt64(&s.stats.TotalBytes, written)
	s.addSessionDownload(written)
	return nil
}
func (s *Syncer) verifyArticaFile(filepath string, expectedMD5 string, expectedSize int64) (bool, error) {
	stat, err := os.Stat(filepath)
	if err != nil {
		return false, fmt.Errorf("failed to stat file: %w", err)
	}
	if expectedSize > 0 {
		if stat.Size() != expectedSize {
			return false, nil
		}
	}

	if len(expectedMD5) < 5 {
		return true, nil
	}
	file, err := os.Open(filepath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, fmt.Errorf("failed to compute MD5: %w", err)
	}

	fileMD5 := hex.EncodeToString(hash.Sum(nil))
	return strings.EqualFold(fileMD5, expectedMD5), nil
}

// ==================== Ubuntu Repository Sync ====================

// syncUbuntuRepository synchronizes Ubuntu repositories
func (s *Syncer) syncUbuntuRepository() {
	cfg := s.config.Get()
	s.logger.LogInfo("Starting Ubuntu repository synchronization")

	// Sync each configured Ubuntu release
	for _, releaseName := range cfg.UbuntuReleases {
		releaseConfig := s.config.GetUbuntuReleaseConfig(releaseName)
		s.logger.LogInfo("Syncing Ubuntu release: %s (LTS: %v, Archived: %v)",
			releaseName, releaseConfig.IsLTS, releaseConfig.IsArchived)

		// Determine components to sync for this release
		components := cfg.UbuntuComponents
		if len(releaseConfig.Components) > 0 {
			components = releaseConfig.Components
		}

		// Sync metadata for the main release
		if err := s.syncUbuntuReleaseMetadata(releaseConfig, releaseName); err != nil {
			s.logger.LogError("Failed to sync Ubuntu metadata for %s: %v", releaseName, err)
		}

		// Sync each component/architecture combination
		for _, component := range components {
			for _, arch := range cfg.UbuntuArchs {
				s.setActivity("syncing", fmt.Sprintf("Ubuntu: %s/%s/%s", releaseName, component, arch), releaseName, component, 0, 0)
				if err := s.syncUbuntuReleaseComponent(releaseConfig, releaseName, component, arch); err != nil {
					s.logger.LogError("Failed to sync Ubuntu %s/%s/%s: %v", releaseName, component, arch, err)
					atomic.AddInt64(&s.stats.FailedFiles, 1)
					s.recordFailedFile("", "", err.Error(), releaseName, component)
				}

				// Download packages if enabled
				if cfg.SyncPackages {
					s.setActivity("downloading", fmt.Sprintf("Ubuntu packages: %s/%s/%s", releaseName, component, arch), releaseName, component, 0, 0)
					if err := s.syncUbuntuPackages(releaseConfig, releaseName, component, arch); err != nil {
						s.logger.LogError("Failed to sync Ubuntu packages for %s/%s/%s: %v", releaseName, component, arch, err)
					}
				}

				// Check disk space
				exceeded, _, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
				if err != nil {
					s.logger.LogError("Failed to check disk space: %v", err)
				}
				if exceeded {
					s.logger.LogError("Disk space limit reached during Ubuntu sync, stopping")
					return
				}
			}
		}

		// Sync additional pockets (-updates, -backports, -security, -proposed)
		if err := s.syncUbuntuAdditionalPockets(releaseConfig, releaseName, components); err != nil {
			s.logger.LogError("Failed to sync Ubuntu additional pockets for %s: %v", releaseName, err)
		}
	}

	s.logger.LogInfo("Ubuntu repository synchronization completed")
}

// syncUbuntuReleaseMetadata downloads Release, Release.gpg, InRelease files for an Ubuntu release
func (s *Syncer) syncUbuntuReleaseMetadata(releaseConfig config.UbuntuReleaseConfig, releaseName string) error {
	cfg := s.config.Get()

	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = cfg.UbuntuMirror
	}

	remoteBase := fmt.Sprintf("%s/dists/%s", mirrorURL, releaseName)
	localBase := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", releaseName)

	if err := os.MkdirAll(localBase, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", localBase, err)
	}

	metadataFiles := []string{"Release", "Release.gpg", "InRelease"}
	for _, file := range metadataFiles {
		remoteURL := fmt.Sprintf("%s/%s", remoteBase, file)
		localPath := filepath.Join(localBase, file)

		if err := s.downloadFileResume(remoteURL, localPath); err != nil {
			if file != "Release.gpg" {
				s.logger.LogError("Failed to download Ubuntu %s/%s: %v", releaseName, file, err)
			}
			continue
		}
		s.logger.LogSync("Downloaded Ubuntu metadata: %s/%s", releaseName, file)
		atomic.AddInt64(&s.stats.TotalFiles, 1)
	}

	return nil
}

// syncUbuntuReleaseComponent downloads Packages index files for an Ubuntu component
func (s *Syncer) syncUbuntuReleaseComponent(releaseConfig config.UbuntuReleaseConfig, releaseName, component, arch string) error {
	cfg := s.config.Get()

	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = cfg.UbuntuMirror
	}

	remoteBase := fmt.Sprintf("%s/dists/%s/%s", mirrorURL, releaseName, component)
	localBase := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", releaseName, component)

	// Create directory for binary-<arch>
	binaryDir := filepath.Join(localBase, fmt.Sprintf("binary-%s", arch))
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	successCount := 0

	// Download Packages.gz with .xz fallback (generates .gz from .xz if needed)
	packagesGzTarget := fmt.Sprintf("binary-%s/Packages.gz", arch)
	if err := s.downloadIndexFileWithXzFallback(remoteBase, localBase, packagesGzTarget); err == nil {
		s.logger.LogSync("Downloaded Ubuntu: %s/%s/%s", releaseName, component, packagesGzTarget)
		atomic.AddInt64(&s.stats.TotalFiles, 1)
		successCount++
	}

	// Also try to download Packages.xz directly (some clients prefer it)
	packagesXzTarget := fmt.Sprintf("binary-%s/Packages.xz", arch)
	remoteURL := fmt.Sprintf("%s/%s", remoteBase, packagesXzTarget)
	localPath := filepath.Join(localBase, packagesXzTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded Ubuntu: %s/%s/%s", releaseName, component, packagesXzTarget)
		atomic.AddInt64(&s.stats.TotalFiles, 1)
		successCount++
	}

	// Download Release file (optional)
	releaseTarget := fmt.Sprintf("binary-%s/Release", arch)
	remoteURL = fmt.Sprintf("%s/%s", remoteBase, releaseTarget)
	localPath = filepath.Join(localBase, releaseTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded Ubuntu: %s/%s/%s", releaseName, component, releaseTarget)
		atomic.AddInt64(&s.stats.TotalFiles, 1)
	}

	if successCount == 0 {
		return fmt.Errorf("failed to download any index files for Ubuntu %s/%s/%s", releaseName, component, arch)
	}

	// Ensure .gz file exists (generate from .xz if missing)
	s.ensureGzFilesFromXz(binaryDir)

	return nil
}

// syncUbuntuPackages downloads .deb packages for an Ubuntu release based on its Packages index
func (s *Syncer) syncUbuntuPackages(releaseConfig config.UbuntuReleaseConfig, releaseName, component, arch string) error {
	cfg := s.config.Get()

	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = cfg.UbuntuMirror
	}

	// Find Packages file - prefer .xz as it's more commonly available now
	packagesPath := ""
	xzPath := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", releaseName, component, fmt.Sprintf("binary-%s", arch), "Packages.xz")
	gzPath := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", releaseName, component, fmt.Sprintf("binary-%s", arch), "Packages.gz")

	if stat, err := os.Stat(xzPath); err == nil && stat.Size() > 0 {
		packagesPath = xzPath
	} else if stat, err := os.Stat(gzPath); err == nil && stat.Size() > 0 {
		packagesPath = gzPath
	}

	if packagesPath == "" {
		s.logger.LogInfo("No valid Packages file found for Ubuntu %s/%s/%s, skipping package sync", releaseName, component, arch)
		return nil
	}

	// Parse Packages file
	packages, err := s.parsePackagesFile(packagesPath)
	if err != nil {
		return fmt.Errorf("failed to parse Ubuntu Packages file: %w", err)
	}

	if len(packages) == 0 {
		s.logger.LogInfo("No packages found in Ubuntu %s/%s/%s", releaseName, component, arch)
		return nil
	}

	s.logger.LogInfo("Found %d packages in Ubuntu %s/%s/%s", len(packages), releaseName, component, arch)

	// Create download jobs
	var jobs []DownloadJob
	for _, pkg := range packages {
		// Ubuntu uses pool/ structure like Debian
		localPath := filepath.Join(cfg.RepositoryPath, "ubuntu", pkg.Filename)

		// Check if file already exists with correct size
		if stat, err := os.Stat(localPath); err == nil {
			if stat.Size() == pkg.Size {
				continue
			}
		}

		jobs = append(jobs, DownloadJob{
			URL:                fmt.Sprintf("%s/%s", mirrorURL, pkg.Filename),
			LocalPath:          localPath,
			ReleaseName:        releaseName,
			RelativePath:       pkg.Filename,
			PackageName:        pkg.Package,
			PackageVersion:     pkg.Version,
			PackageDescription: pkg.Description,
			PackageSize:        pkg.Size,
			Component:          component,
			Architecture:       arch,
		})
	}

	if len(jobs) == 0 {
		s.logger.LogInfo("All Ubuntu packages up to date for %s/%s/%s", releaseName, component, arch)
		return nil
	}

	s.logger.LogInfo("Downloading %d Ubuntu packages for %s/%s/%s", len(jobs), releaseName, component, arch)

	// Download in batches
	batchSize := 100
	for i := 0; i < len(jobs); i += batchSize {
		end := i + batchSize
		if end > len(jobs) {
			end = len(jobs)
		}

		batch := jobs[i:end]
		results := s.downloadFilesParallel(batch)

		for _, result := range results {
			if result.Error != nil {
				s.logger.LogError("Failed to download Ubuntu package %s: %v", result.Job.URL, result.Error)
				atomic.AddInt64(&s.stats.FailedFiles, 1)
			} else {
				atomic.AddInt64(&s.stats.TotalFiles, 1)
			}
		}

		// Check disk space
		exceeded, _, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
		if err != nil {
			s.logger.LogError("Failed to check disk space: %v", err)
		}
		if exceeded {
			s.logger.LogError("Disk space limit reached during Ubuntu package sync, stopping")
			return fmt.Errorf("disk space exceeded")
		}
	}

	return nil
}

// syncUbuntuAdditionalPockets syncs -updates, -backports, -security, -proposed pockets
func (s *Syncer) syncUbuntuAdditionalPockets(releaseConfig config.UbuntuReleaseConfig, releaseName string, components []string) error {
	cfg := s.config.Get()
	var syncError error

	mirrorURL := releaseConfig.Mirror
	if mirrorURL == "" {
		mirrorURL = cfg.UbuntuMirror
	}

	// Ubuntu pocket suffixes (similar to Debian suites)
	// -updates: Regular updates
	// -security: Security updates
	// -backports: Backported packages from newer releases
	// -proposed: Pre-release updates (testing)

	// Sync -updates pocket if enabled
	if releaseConfig.SyncUpdates {
		updatesPocket := releaseName + "-updates"
		s.logger.LogInfo("Syncing Ubuntu updates pocket: %s", updatesPocket)
		if err := s.syncUbuntuPocket(mirrorURL, updatesPocket, components, cfg.UbuntuArchs); err != nil {
			s.logger.LogError("Failed to sync Ubuntu updates for %s: %v", releaseName, err)
			syncError = err
		}
	}

	// Sync -security pocket if enabled
	if releaseConfig.SyncSecurity {
		securityPocket := releaseName + "-security"
		// Security updates may come from a different mirror (security.ubuntu.com)
		securityMirror := mirrorURL
		if !releaseConfig.IsArchived {
			securityMirror = "http://security.ubuntu.com/ubuntu"
		}
		s.logger.LogInfo("Syncing Ubuntu security pocket: %s from %s", securityPocket, securityMirror)
		if err := s.syncUbuntuPocket(securityMirror, securityPocket, components, cfg.UbuntuArchs); err != nil {
			s.logger.LogError("Failed to sync Ubuntu security for %s: %v", releaseName, err)
			syncError = err
		}
	}

	// Sync -backports pocket if enabled
	if releaseConfig.SyncBackports {
		backportsPocket := releaseName + "-backports"
		s.logger.LogInfo("Syncing Ubuntu backports pocket: %s", backportsPocket)
		if err := s.syncUbuntuPocket(mirrorURL, backportsPocket, components, cfg.UbuntuArchs); err != nil {
			s.logger.LogError("Failed to sync Ubuntu backports for %s: %v", releaseName, err)
			syncError = err
		}
	}

	// Sync -proposed pocket if enabled (usually disabled for production)
	if releaseConfig.SyncProposed {
		proposedPocket := releaseName + "-proposed"
		s.logger.LogInfo("Syncing Ubuntu proposed pocket: %s", proposedPocket)
		if err := s.syncUbuntuPocket(mirrorURL, proposedPocket, components, cfg.UbuntuArchs); err != nil {
			s.logger.LogError("Failed to sync Ubuntu proposed for %s: %v", releaseName, err)
			syncError = err
		}
	}

	return syncError
}

// syncUbuntuPocket syncs a specific Ubuntu pocket (e.g., jammy-updates, jammy-security)
func (s *Syncer) syncUbuntuPocket(mirrorURL, pocket string, components, architectures []string) error {
	cfg := s.config.Get()

	// Sync metadata for this pocket
	if err := s.syncUbuntuPocketMetadata(mirrorURL, pocket); err != nil {
		s.logger.LogError("Failed to sync Ubuntu metadata for pocket %s: %v", pocket, err)
	}

	// Sync each component/architecture
	for _, component := range components {
		for _, arch := range architectures {
			if err := s.syncUbuntuPocketComponent(mirrorURL, pocket, component, arch); err != nil {
				s.logger.LogError("Failed to sync Ubuntu %s/%s/%s: %v", pocket, component, arch, err)
				continue
			}

			// Download packages if enabled
			if cfg.SyncPackages {
				if err := s.syncUbuntuPocketPackages(mirrorURL, pocket, component, arch); err != nil {
					s.logger.LogError("Failed to sync Ubuntu packages for %s/%s/%s: %v", pocket, component, arch, err)
				}
			}
		}
	}

	return nil
}

// syncUbuntuPocketMetadata downloads Release, Release.gpg, InRelease files for an Ubuntu pocket
func (s *Syncer) syncUbuntuPocketMetadata(mirrorURL, pocket string) error {
	cfg := s.config.Get()

	remoteBase := fmt.Sprintf("%s/dists/%s", mirrorURL, pocket)
	localBase := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", pocket)

	if err := os.MkdirAll(localBase, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", localBase, err)
	}

	metadataFiles := []string{"Release", "Release.gpg", "InRelease"}
	for _, file := range metadataFiles {
		remoteURL := fmt.Sprintf("%s/%s", remoteBase, file)
		localPath := filepath.Join(localBase, file)

		if err := s.downloadFileResume(remoteURL, localPath); err != nil {
			if file != "Release.gpg" {
				s.logger.LogError("Failed to download Ubuntu pocket %s/%s: %v", pocket, file, err)
			}
			continue
		}
		s.logger.LogSync("Downloaded Ubuntu pocket metadata: %s/%s", pocket, file)
	}

	return nil
}

// syncUbuntuPocketComponent downloads Packages index files for an Ubuntu pocket component
func (s *Syncer) syncUbuntuPocketComponent(mirrorURL, pocket, component, arch string) error {
	cfg := s.config.Get()

	remoteBase := fmt.Sprintf("%s/dists/%s/%s", mirrorURL, pocket, component)
	localBase := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", pocket, component)

	// Create directory for binary-<arch>
	binaryDir := filepath.Join(localBase, fmt.Sprintf("binary-%s", arch))
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	successCount := 0

	// Download Packages.gz with .xz fallback (generates .gz from .xz if needed)
	packagesGzTarget := fmt.Sprintf("binary-%s/Packages.gz", arch)
	if err := s.downloadIndexFileWithXzFallback(remoteBase, localBase, packagesGzTarget); err == nil {
		s.logger.LogSync("Downloaded Ubuntu pocket: %s/%s/%s", pocket, component, packagesGzTarget)
		successCount++
	}

	// Also try to download Packages.xz directly (some clients prefer it)
	packagesXzTarget := fmt.Sprintf("binary-%s/Packages.xz", arch)
	remoteURL := fmt.Sprintf("%s/%s", remoteBase, packagesXzTarget)
	localPath := filepath.Join(localBase, packagesXzTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded Ubuntu pocket: %s/%s/%s", pocket, component, packagesXzTarget)
		successCount++
	}

	// Download Release file (optional)
	releaseTarget := fmt.Sprintf("binary-%s/Release", arch)
	remoteURL = fmt.Sprintf("%s/%s", remoteBase, releaseTarget)
	localPath = filepath.Join(localBase, releaseTarget)
	if err := s.downloadFileResume(remoteURL, localPath); err == nil {
		s.logger.LogSync("Downloaded Ubuntu pocket: %s/%s/%s", pocket, component, releaseTarget)
	}

	if successCount == 0 {
		return fmt.Errorf("failed to download any index files for Ubuntu pocket %s/%s/%s", pocket, component, arch)
	}

	// Ensure .gz file exists (generate from .xz if missing)
	s.ensureGzFilesFromXz(binaryDir)

	return nil
}

// syncUbuntuPocketPackages downloads .deb packages for an Ubuntu pocket based on its Packages index
func (s *Syncer) syncUbuntuPocketPackages(mirrorURL, pocket, component, arch string) error {
	cfg := s.config.Get()

	// Find Packages file
	packagesPath := ""
	xzPath := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", pocket, component, fmt.Sprintf("binary-%s", arch), "Packages.xz")
	gzPath := filepath.Join(cfg.RepositoryPath, "ubuntu", "dists", pocket, component, fmt.Sprintf("binary-%s", arch), "Packages.gz")

	if stat, err := os.Stat(xzPath); err == nil && stat.Size() > 0 {
		packagesPath = xzPath
	} else if stat, err := os.Stat(gzPath); err == nil && stat.Size() > 0 {
		packagesPath = gzPath
	}

	if packagesPath == "" {
		s.logger.LogInfo("No valid Packages file found for Ubuntu pocket %s/%s/%s, skipping", pocket, component, arch)
		return nil
	}

	// Parse Packages file
	packages, err := s.parsePackagesFile(packagesPath)
	if err != nil {
		return fmt.Errorf("failed to parse Ubuntu Packages file: %w", err)
	}

	if len(packages) == 0 {
		s.logger.LogInfo("No packages found in Ubuntu pocket %s/%s/%s", pocket, component, arch)
		return nil
	}

	s.logger.LogInfo("Found %d packages in Ubuntu pocket %s/%s/%s", len(packages), pocket, component, arch)

	// Create download jobs
	var jobs []DownloadJob
	for _, pkg := range packages {
		localPath := filepath.Join(cfg.RepositoryPath, "ubuntu", pkg.Filename)

		// Check if file already exists with correct size
		if stat, err := os.Stat(localPath); err == nil {
			if stat.Size() == pkg.Size {
				continue
			}
		}

		jobs = append(jobs, DownloadJob{
			URL:                fmt.Sprintf("%s/%s", mirrorURL, pkg.Filename),
			LocalPath:          localPath,
			ReleaseName:        pocket,
			RelativePath:       pkg.Filename,
			PackageName:        pkg.Package,
			PackageVersion:     pkg.Version,
			PackageDescription: pkg.Description,
			PackageSize:        pkg.Size,
			Component:          component,
			Architecture:       arch,
		})
	}

	if len(jobs) == 0 {
		s.logger.LogInfo("All Ubuntu packages up to date for pocket %s/%s/%s", pocket, component, arch)
		return nil
	}

	s.logger.LogInfo("Downloading %d Ubuntu packages for pocket %s/%s/%s", len(jobs), pocket, component, arch)

	// Download in batches
	batchSize := 100
	for i := 0; i < len(jobs); i += batchSize {
		end := i + batchSize
		if end > len(jobs) {
			end = len(jobs)
		}

		batch := jobs[i:end]
		results := s.downloadFilesParallel(batch)

		for _, result := range results {
			if result.Error != nil {
				s.logger.LogError("Failed to download Ubuntu pocket package %s: %v", result.Job.URL, result.Error)
				atomic.AddInt64(&s.stats.FailedFiles, 1)
			} else {
				atomic.AddInt64(&s.stats.TotalFiles, 1)
			}
		}

		// Check disk space
		exceeded, _, err := utils.CheckDiskSpace(cfg.RepositoryPath, cfg.MaxDiskUsagePercent)
		if err != nil {
			s.logger.LogError("Failed to check disk space: %v", err)
		}
		if exceeded {
			s.logger.LogError("Disk space limit reached during Ubuntu pocket package sync, stopping")
			return fmt.Errorf("disk space exceeded")
		}
	}

	return nil
}
