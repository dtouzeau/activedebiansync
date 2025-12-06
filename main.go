package main

import (
	"activedebiansync/api"
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/gpg"
	"activedebiansync/metrics"
	pkgmanager "activedebiansync/package"
	"activedebiansync/scheduler"
	"activedebiansync/server"
	"activedebiansync/sync"
	"activedebiansync/utils"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	AppName = "ActiveDebianSync"
)

func main() {

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "package":
			handlePackageCommand()
			return
		case "gpg":
			handleGPGCommand()
			return
		case "version", "-version", "--version":
			fmt.Printf("%s v%s\n", AppName, version)
			os.Exit(0)
		case "help", "-help", "--help":
			printHelp()
			os.Exit(0)
		}
	}
	startDaemon()
}

func startDaemon() {

	configPath := flag.String("config", config.DefaultConfigPath, "Path to configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialiser le logger
	if err := utils.InitLogger(cfg.Get().LogPath, cfg.Get().AccessLogPath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger := utils.GetLogger()
	defer func(logger *utils.Logger) {
		_ = logger.Close()
	}(logger)

	logger.LogInfo("=== %s v%s Starting ===", AppName, version)
	logger.LogInfo("Configuration loaded from: %s", *configPath)

	cfgData := cfg.Get()
	pidFile := utils.NewPIDFile(cfgData.PIDFile)
	if err := pidFile.Write(); err != nil {
		logger.LogError("Failed to create PID file: %v", err)
		os.Exit(1)
	}
	defer func(pidFile *utils.PIDFile) {
		err := pidFile.Remove()
		if err != nil {
			logger.LogError("Failed to remove PID file: %v", err)
		}
	}(pidFile)
	logger.LogInfo("PID file created: %s (PID: %d)", pidFile.GetPath(), os.Getpid())

	if err := utils.ValidateUserGroup(cfgData.RunAsUser, cfgData.RunAsGroup); err != nil {
		logger.LogError("Invalid user/group configuration: %v", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfgData.RepositoryPath, 0755); err != nil {
		logger.LogError("Failed to create repository directory: %v", err)
		os.Exit(1)
	}

	if cfgData.RunAsUser != "" {
		currentUser, currentGroup, _ := utils.GetCurrentUser()
		logger.LogInfo("Current user: %s:%s", currentUser, currentGroup)

		targetGroup := cfgData.RunAsGroup
		if targetGroup == "" {
			targetGroup = "(primary group)"
		}
		logger.LogInfo("Switching to user: %s:%s", cfgData.RunAsUser, targetGroup)

		if err := utils.SwitchUser(cfgData.RunAsUser, cfgData.RunAsGroup); err != nil {
			logger.LogError("Failed to switch user: %v", err)
			os.Exit(1)
		}

		newUser, newGroup, _ := utils.GetCurrentUser()
		logger.LogInfo("Successfully switched to user: %s:%s", newUser, newGroup)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	gpgManager := gpg.NewGPGManager(cfg, logger)
	syncer := sync.NewSyncer(cfg, logger, gpgManager)
	httpServer := server.NewHTTPServer(cfg, logger)
	httpServer.SetSyncChecker(syncer)
	httpServer.SetAnalytics(syncer.GetAnalytics())
	pkgManager := pkgmanager.NewPackageManager(cfg, logger, gpgManager)
	restAPI := api.NewRestAPI(cfg, logger, syncer, httpServer, pkgManager, gpgManager, syncer)

	// Initialiser la base de données des mises à jour de packages
	updatesDB, err := database.NewUpdatesDB(*configPath)
	if err != nil {
		logger.LogError("Failed to initialize package updates database: %v", err)
		logger.LogError("Package update tracking will be disabled")
	} else {
		syncer.SetUpdatesDB(updatesDB)
		if updatesDB.IsFirstSync() {
			logger.LogInfo("First sync detected - package updates will not be recorded until first sync completes")
		} else {
			logger.LogInfo("Package updates database initialized: %s", updatesDB.GetDBPath())
		}
		defer func() {
			if err := updatesDB.Close(); err != nil {
				logger.LogError("Failed to close updates database: %v", err)
			}
		}()
	}

	// Initialiser la base de données de recherche de packages (si activée)
	if cfgData.PackageSearchEnabled {
		searchDB, err := database.NewPackageSearchDB(*configPath)
		if err != nil {
			logger.LogError("Failed to initialize package search database: %v", err)
			logger.LogError("Package search will be disabled")
		} else {
			syncer.SetSearchDB(searchDB)
			restAPI.SetSearchDB(searchDB)
			logger.LogInfo("Package search database initialized: %s", searchDB.GetDBPath())
			defer func() {
				if err := searchDB.Close(); err != nil {
					logger.LogError("Failed to close search database: %v", err)
				}
			}()
		}
	}

	// Initialiser la persistence des métriques
	metricsPersistence := metrics.NewMetricsPersistence(*configPath)

	// Charger les métriques persistées si elles existent
	if metricsPersistence.Exists() {
		persistedMetrics, err := metricsPersistence.Load()
		if err != nil {
			logger.LogError("Failed to load persisted metrics: %v", err)
		} else if persistedMetrics != nil {
			logger.LogInfo("Loading persisted metrics from %s (saved at %s)",
				metricsPersistence.GetFilePath(), persistedMetrics.SavedAt.Format(time.RFC3339))

			// Charger les stats de sync
			syncer.LoadStats(
				persistedMetrics.SyncTotalFiles,
				persistedMetrics.SyncTotalBytes,
				persistedMetrics.SyncFailedFiles,
				persistedMetrics.SyncLastStart,
				persistedMetrics.SyncLastEnd,
				persistedMetrics.SyncLastDuration,
				persistedMetrics.SyncLastError,
			)

			// Charger les stats du serveur HTTP
			httpServer.LoadStats(
				persistedMetrics.ServerTotalRequests,
				persistedMetrics.ServerTotalBytesSent,
			)

			// Charger les clients
			if len(persistedMetrics.Clients) > 0 {
				var clients []server.ClientInfo
				for _, c := range persistedMetrics.Clients {
					clients = append(clients, server.ClientInfo{
						IP:            c.IP,
						Hostname:      c.Hostname,
						FirstSeen:     c.FirstSeen,
						LastSeen:      c.LastSeen,
						RequestCount:  c.RequestCount,
						BytesReceived: c.BytesReceived,
					})
				}
				httpServer.LoadClients(clients)
				logger.LogInfo("Loaded %d persisted clients", len(clients))
			}

			logger.LogInfo("Persisted metrics loaded successfully")
		}
	}

	if cfgData.GPGSigningEnabled {
		newKeyGenerated, err := gpgManager.InitializeOrLoadKey()
		if err != nil {
			logger.LogError("Failed to initialize GPG key: %v", err)
			logger.LogError("GPG signing will be disabled")
		} else {
			if newKeyGenerated {
				logger.LogInfo("GPG signing enabled (new key pair generated automatically)")
			} else {
				logger.LogInfo("GPG signing enabled (existing key loaded)")
			}
		}
	}

	errChan := make(chan error, 3)

	go func() {
		syncer.Start(ctx)
	}()

	optScheduler := scheduler.NewScheduler(cfg, logger, syncer.GetOptimizer())
	go optScheduler.Start(ctx)

	// Démarrer le vérificateur d'index de recherche
	// Ce scheduler vérifie périodiquement si les index existent et les crée si nécessaire
	// (utile quand sync_contents passe de false à true)
	go syncer.StartSearchIndexChecker(ctx)

	go func() {
		analytics := syncer.GetAnalytics()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				if err := analytics.Save(); err != nil {
					logger.LogError("Failed to save analytics on shutdown: %v", err)
				} else {
					logger.LogInfo("Analytics saved successfully on shutdown")
				}
				return
			case <-ticker.C:
				if err := analytics.Save(); err != nil {
					logger.LogError("Failed to save analytics: %v", err)
				}
			}
		}
	}()
	go func() {
		if err := httpServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	go func() {
		if err := restAPI.Start(ctx); err != nil {
			errChan <- fmt.Errorf("REST API error: %w", err)
		}
	}()

	logger.LogInfo("All services started successfully")
	logger.LogInfo("HTTP Server: %v (port %d)", cfgData.HTTPEnabled, cfgData.HTTPPort)
	logger.LogInfo("HTTPS Server: %v (port %d)", cfgData.HTTPSEnabled, cfgData.HTTPSPort)
	logger.LogInfo("REST API: %v (%s:%d)", cfgData.APIEnabled, cfgData.APIListenAddr, cfgData.APIPort)
	logger.LogInfo("Repository Path: %s", cfgData.RepositoryPath)
	logger.LogInfo("Sync Interval: %d minutes", cfgData.SyncInterval)

	if cfgData.APIEnabled {
		logger.LogInfo("REST API Endpoints:")
		logger.LogInfo("  - GET  http://%s:%d/api/status", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/sync/stats", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - POST http://%s:%d/api/sync/trigger", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/server/stats", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/clients", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/disk", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/updates/check", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/health", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - POST http://%s:%d/api/packages/upload", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - GET  http://%s:%d/api/packages/list", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - POST http://%s:%d/api/packages/remove", cfgData.APIListenAddr, cfgData.APIPort)
		logger.LogInfo("  - POST http://%s:%d/api/packages/regenerate", cfgData.APIListenAddr, cfgData.APIPort)
		if cfgData.PackageSearchEnabled {
			logger.LogInfo("Package Search API:")
			logger.LogInfo("  - GET  http://%s:%d/api/search?q=<query>", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/search/file?path=<path>", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/search/package?name=<name>", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/search/package-files?package=<name>", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/search/status", cfgData.APIListenAddr, cfgData.APIPort)
		}
		if cfgData.GPGSigningEnabled {
			logger.LogInfo("GPG Signing API:")
			logger.LogInfo("  - GET  http://%s:%d/api/gpg/status", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/gpg/info", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - POST http://%s:%d/api/gpg/generate", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - POST http://%s:%d/api/gpg/sign", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/gpg/export", cfgData.APIListenAddr, cfgData.APIPort)
			logger.LogInfo("  - GET  http://%s:%d/api/gpg-key (public, no auth)", cfgData.APIListenAddr, cfgData.APIPort)
		}
	}

	select {
	case sig := <-sigChan:
		logger.LogInfo("Received signal: %v", sig)
		logger.LogInfo("Shutting down gracefully...")
		cancel()
	case err := <-errChan:
		logger.LogError("Fatal error: %v", err)
		cancel()
	}

	// Sauvegarder les métriques avant l'arrêt
	logger.LogInfo("Saving metrics to %s...", metricsPersistence.GetFilePath())
	syncStats := syncer.GetStats()
	serverStats := httpServer.GetStats()
	clientList := httpServer.GetClients()

	persistedMetrics := &metrics.PersistedMetrics{
		// Sync stats
		SyncTotalFiles:   syncStats.TotalFiles,
		SyncTotalBytes:   syncStats.TotalBytes,
		SyncFailedFiles:  syncStats.FailedFiles,
		SyncLastStart:    syncStats.LastSyncStart,
		SyncLastEnd:      syncStats.LastSyncEnd,
		SyncLastDuration: syncStats.LastSyncDuration,
		SyncLastError:    syncStats.LastError,

		// Server stats
		ServerTotalRequests:  serverStats.TotalRequests,
		ServerTotalBytesSent: serverStats.TotalBytesSent,
	}

	// Convertir les clients
	for _, c := range clientList {
		persistedMetrics.Clients = append(persistedMetrics.Clients, metrics.PersistedClient{
			IP:            c.IP,
			Hostname:      c.Hostname,
			FirstSeen:     c.FirstSeen,
			LastSeen:      c.LastSeen,
			RequestCount:  c.RequestCount,
			BytesReceived: c.BytesReceived,
		})
	}

	if err := metricsPersistence.Save(persistedMetrics); err != nil {
		logger.LogError("Failed to save metrics: %v", err)
	} else {
		logger.LogInfo("Metrics saved successfully (%d sync files, %d server requests, %d clients)",
			syncStats.TotalFiles, serverStats.TotalRequests, len(clientList))
	}

	logger.LogInfo("Removing PID file: %s", pidFile.GetPath())
	logger.LogInfo("=== %s Stopped ===", AppName)
}

func printHelp() {
	fmt.Printf("%s v%s - Debian Repository Synchronization Daemon\n\n", AppName, version)
	fmt.Println("Usage:")
	fmt.Printf("  %s [command] [options]\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  (none)         Start daemon (default)")
	fmt.Println("  package        Manage custom packages (see 'package help')")
	fmt.Println("  version        Show version")
	fmt.Println("  help           Show this help")
	fmt.Println("\nDaemon Options:")
	fmt.Println("  -config <path>  Path to configuration file (default: /etc/ActiveDebianSync/config.json)")
	fmt.Println("\nConfiguration:")
	fmt.Printf("  Default config path: %s\n", config.DefaultConfigPath)
	fmt.Println("  Config format: JSON")
	fmt.Println("\nFeatures:")
	fmt.Println("  - Incremental Debian repository synchronization")
	fmt.Println("  - HTTP/HTTPS server for APT repository")
	fmt.Println("  - REST API for monitoring and statistics")
	fmt.Println("  - Automatic resume on download errors")
	fmt.Println("  - Disk space monitoring and limits")
	fmt.Println("  - Client tracking and access logging")
	fmt.Println("  - IP-based access control for REST API")
	fmt.Println("\nSupported Debian versions:")
	fmt.Println("  - Debian 12 (Bookworm)")
	fmt.Println("  - Debian 13 (Trixie)")
	fmt.Println("\nREST API Endpoints:")
	fmt.Println("  GET  /api/status         - General status and statistics")
	fmt.Println("  GET  /api/sync/stats     - Synchronization statistics")
	fmt.Println("  POST /api/sync/trigger   - Trigger manual sync")
	fmt.Println("  GET  /api/server/stats   - HTTP server statistics")
	fmt.Println("  GET  /api/clients        - Connected clients information")
	fmt.Println("  GET  /api/disk           - Disk space information")
	fmt.Println("  GET  /api/updates/check  - Check for available updates")
	fmt.Println("  GET  /api/health         - Health check (no auth)")
	fmt.Println("\nPackage Management API:")
	fmt.Println("  POST /api/packages/upload       - Upload custom .deb package")
	fmt.Println("  GET  /api/packages/list         - List custom packages")
	fmt.Println("  POST /api/packages/remove       - Remove a package")
	fmt.Println("  POST /api/packages/regenerate   - Regenerate indexes")
	fmt.Println("\nPackage Search API (like apt-file):")
	fmt.Println("  GET  /api/search?q=<query>               - Search packages (name, description, files)")
	fmt.Println("  GET  /api/search/file?path=<path>        - Search by file path (like apt-file search)")
	fmt.Println("  GET  /api/search/package?name=<name>     - Search by package name")
	fmt.Println("  GET  /api/search/description?q=<query>   - Search by description")
	fmt.Println("  GET  /api/search/package-files?package=<name> - List files in package (like apt-file list)")
	fmt.Println("  GET  /api/search/package-info?package=<name>  - Get package details")
	fmt.Println("  GET  /api/search/status                  - Get search index status")
	fmt.Println("\nGPG Signing API:")
	fmt.Println("  GET  /api/gpg/status                     - Get GPG signing status")
	fmt.Println("  GET  /api/gpg/info                       - Get GPG key information")
	fmt.Println("  POST /api/gpg/generate                   - Generate new GPG key pair")
	fmt.Println("  POST /api/gpg/sign                       - Sign all Release files")
	fmt.Println("  GET  /api/gpg/export                     - Export public key (PGP armored)")
	fmt.Println("  GET  /api/gpg/export?format=json         - Export public key (JSON)")
	fmt.Println("  GET  /api/gpg/instructions               - Get client setup instructions")
	fmt.Println("  GET  /api/gpg-key                        - Download public key (no auth)")
	fmt.Println("\nExamples:")
	fmt.Println("  # Start with default config")
	fmt.Printf("  %s\n\n", os.Args[0])
	fmt.Println("  # Start with custom config")
	fmt.Printf("  %s -config /etc/myconfig.json\n\n", os.Args[0])
	fmt.Println("  # Check API status")
	fmt.Println("  curl http://127.0.0.1:9090/api/status | jq")
	fmt.Println("\n  # Trigger manual sync")
	fmt.Println("  curl -X POST http://127.0.0.1:9090/api/sync/trigger")
	fmt.Println("\n  # Add a custom package (CLI)")
	fmt.Printf("  %s package add myapp_1.0.0_amd64.deb bookworm main amd64\n", os.Args[0])
	fmt.Println("\n  # Upload a package (API)")
	fmt.Println("  curl -F 'package=@myapp.deb' -F 'release=bookworm' -F 'component=main' -F 'architecture=amd64' http://127.0.0.1:9090/api/packages/upload")
	fmt.Println("\n  # Generate GPG key and sign repository (API)")
	fmt.Println("  curl -X POST http://127.0.0.1:9090/api/gpg/generate")
	fmt.Println("  curl -X POST http://127.0.0.1:9090/api/gpg/sign")
	fmt.Println("\n  # Get client setup instructions")
	fmt.Println("  curl http://127.0.0.1:9090/api/gpg/instructions")
	fmt.Println("\nFor more information, see README.md")
}
