package main

import (
	"activedebiansync/articarepos"
	"activedebiansync/config"
	"activedebiansync/sync"
	"activedebiansync/utils"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// handleArticaCommand gère les commandes de gestion des packages Artica
func handleArticaCommand() {
	if len(os.Args) < 3 {
		printArticaHelp()
		os.Exit(1)
	}

	articaCmd := flag.NewFlagSet("artica", flag.ExitOnError)
	configPath := articaCmd.String("config", config.DefaultConfigPath, "Path to configuration file")

	// Parse les flags après la sous-commande
	articaCmd.Parse(os.Args[2:])

	// Charger la configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Récupérer la sous-commande
	action := articaCmd.Arg(0)

	switch action {
	case "build":
		handleArticaBuild(cfg, articaCmd.Args())
	case "build-all":
		handleArticaBuildAll(cfg, articaCmd.Args())
	case "install":
		handleArticaInstall(articaCmd.Args())
	case "remove":
		handleArticaRemove(articaCmd.Args())
	case "list":
		handleArticaList()
	case "info":
		handleArticaInfo(articaCmd.Args())
	case "sync":
		handleArticaSync(cfg)
	case "sync-cores":
		handleArticaSyncCores(cfg)
	case "cleanup":
		handleArticaCleanup(articaCmd.Args())
	case "help", "-help", "--help":
		printArticaHelp()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown artica command: %s\n", action)
		printArticaHelp()
		os.Exit(1)
	}
}

// handleArticaBuild construit un package .deb à partir d'un tar.gz Artica
func handleArticaBuild(cfg *config.Config, args []string) {
	if len(args) < 4 {
		fmt.Println("Usage: activedebiansync artica build <product-code> <version> <tar.gz-path>")
		fmt.Println("Example: activedebiansync artica build APP_NGINX 1.2.3 /path/to/package.tar.gz")
		os.Exit(1)
	}

	productCode := args[1]
	version := args[2]
	tarGzPath := args[3]

	// Vérifier que le fichier existe
	if _, err := os.Stat(tarGzPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: tar.gz file not found: %s\n", tarGzPath)
		os.Exit(1)
	}

	fmt.Printf("Building .deb package for %s v%s\n", productCode, version)
	fmt.Printf("Source: %s\n", tarGzPath)

	// Créer la structure ArticaSoft
	cfgData := cfg.Get()
	soft := articarepos.ArticaSoft{
		ProductCode: productCode,
		Version:     version,
		Tempfile:    tarGzPath,
		TempDir:     filepath.Join(cfgData.RepositoryPath, "artica-src", "manual", productCode),
	}

	result, err := articarepos.BuildDebPackage(soft)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build .deb: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Package built successfully\n")
	fmt.Printf("  .deb file: %s\n", result.DebPath)
	fmt.Printf("  Extracted to: %s\n", result.ExtractPath)
}

// handleArticaBuildAll construit tous les packages depuis les sources téléchargées
func handleArticaBuildAll(cfg *config.Config, args []string) {
	release := "bookworm"
	if len(args) >= 2 {
		release = args[1]
	}

	cfgData := cfg.Get()
	srcDir := filepath.Join(cfgData.RepositoryPath, "artica-src", release)

	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		fmt.Printf("No Artica sources found for release %s\n", release)
		fmt.Printf("Expected directory: %s\n", srcDir)
		os.Exit(0)
	}

	fmt.Printf("Building all Artica packages from %s\n\n", srcDir)

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read source directory: %v\n", err)
		os.Exit(1)
	}

	successCount := 0
	failCount := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		productCode := entry.Name()
		productDir := filepath.Join(srcDir, productCode)

		// Trouver le fichier tar.gz
		files, err := os.ReadDir(productDir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".tar.gz") {
				tarGzPath := filepath.Join(productDir, file.Name())
				version := strings.TrimSuffix(file.Name(), ".tar.gz")

				fmt.Printf("Building %s v%s... ", productCode, version)

				soft := articarepos.ArticaSoft{
					ProductCode: productCode,
					Version:     version,
					Tempfile:    tarGzPath,
					TempDir:     filepath.Join(articarepos.ArticaDebBasePath, productCode),
				}

				result, err := articarepos.BuildDebPackage(soft)
				if err != nil {
					fmt.Printf("FAILED: %v\n", err)
					failCount++
				} else {
					fmt.Printf("OK -> %s\n", filepath.Base(result.DebPath))
					successCount++
				}
				break
			}
		}
	}

	fmt.Printf("\nBuild complete: %d succeeded, %d failed\n", successCount, failCount)
}

// handleArticaInstall installe un package Artica
func handleArticaInstall(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: activedebiansync artica install <product-code>")
		fmt.Println("Example: activedebiansync artica install APP_NGINX")
		os.Exit(1)
	}

	productCode := args[1]

	fmt.Printf("Installing Artica package: %s\n", productCode)

	if err := articarepos.InstallDebPackage(productCode); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to install: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Package %s installed successfully\n", productCode)
}

// handleArticaRemove désinstalle un package Artica
func handleArticaRemove(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: activedebiansync artica remove <product-code>")
		fmt.Println("Example: activedebiansync artica remove APP_NGINX")
		os.Exit(1)
	}

	productCode := args[1]

	fmt.Printf("Removing Artica package: %s\n", productCode)

	if err := articarepos.RemoveDebPackage(productCode); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Package %s removed successfully\n", productCode)
}

// handleArticaList liste les packages Artica disponibles
func handleArticaList() {
	fmt.Printf("Artica .deb packages in %s:\n\n", articarepos.ArticaDebBasePath)

	packages, err := articarepos.ListArticaDebPackages()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list packages: %v\n", err)
		os.Exit(1)
	}

	if len(packages) == 0 {
		fmt.Println("No .deb packages found")
		return
	}

	for _, pkg := range packages {
		fmt.Printf("  %s\n", pkg)
	}

	fmt.Printf("\nTotal: %d package(s)\n", len(packages))
}

// handleArticaInfo affiche les informations sur un package Artica
func handleArticaInfo(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: activedebiansync artica info <product-code>")
		fmt.Println("Example: activedebiansync artica info APP_NGINX")
		os.Exit(1)
	}

	productCode := args[1]

	info, err := articarepos.GetArticaDebInfo(productCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get package info: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Package Information:\n")
	fmt.Printf("  Product Code: %s\n", info.ProductCode)
	fmt.Printf("  Version: %s\n", info.Version)
	fmt.Printf("  Architecture: %s\n", info.Architecture)
	fmt.Printf("  Extract Path: %s\n", filepath.Join(articarepos.ArticaDebBasePath, productCode))
}

// handleArticaSync synchronise les dépôts Artica et construit les .deb
func handleArticaSync(cfg *config.Config) {
	cfgData := cfg.Get()

	// Vérifier que sync_artica_repository est activé
	if !cfgData.SyncArticaRepository {
		fmt.Println("Artica repository sync is disabled in configuration")
		fmt.Println("Set 'sync_artica_repository': true in config.json to enable")
		os.Exit(1)
	}

	// Initialiser le logger
	if err := utils.InitLogger(cfgData.LogPath, cfgData.AccessLogPath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger := utils.GetLogger()
	defer logger.Close()

	fmt.Println("Synchronizing Artica repositories...")

	// Obtenir les URLs des index Artica
	articaURLs := articarepos.GetArticaRepoUrls(cfg)

	for _, release := range cfgData.DebianReleases {
		indexURL, exists := articaURLs[release]
		if !exists {
			fmt.Printf("No Artica repository URL for release %s, skipping\n", release)
			continue
		}

		fmt.Printf("\nSyncing Artica repository for %s from %s\n", release, indexURL)

		// Télécharger l'index (utiliser HTTP client simple pour la CLI)
		indexContent, err := downloadIndex(indexURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to download index: %v\n", err)
			continue
		}

		// Parser l'index
		err, articaRepo := articarepos.ListArticaReposSrc(cfg, release, indexContent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse index: %v\n", err)
			continue
		}

		fmt.Printf("Found %d packages\n", len(articaRepo.Softs))

		for _, soft := range articaRepo.Softs {
			fmt.Printf("  Processing %s v%s... ", soft.ProductCode, soft.Version)

			// Vérifier si le fichier existe déjà
			if _, err := os.Stat(soft.Tempfile); err == nil {
				// Vérifier MD5
				valid, _ := verifyFile(soft.Tempfile, soft.Md5, soft.Size)
				if valid {
					fmt.Printf("up to date, building .deb... ")
					result, err := articarepos.BuildDebPackage(soft)
					if err != nil {
						fmt.Printf("build FAILED: %v\n", err)
					} else {
						fmt.Printf("OK -> %s\n", filepath.Base(result.DebPath))
					}
					continue
				}
			}

			// Télécharger
			fmt.Printf("downloading... ")
			if err := downloadPackage(soft); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				continue
			}

			// Construire le .deb
			fmt.Printf("building .deb... ")
			result, err := articarepos.BuildDebPackage(soft)
			if err != nil {
				fmt.Printf("build FAILED: %v\n", err)
			} else {
				fmt.Printf("OK -> %s\n", filepath.Base(result.DebPath))
			}
		}
	}

	fmt.Println("\nSync completed")
}

// handleArticaSyncCores synchronise les versions du core Artica
func handleArticaSyncCores(cfg *config.Config) {
	cfgData := cfg.Get()
	if err := utils.InitLogger(cfgData.LogPath, cfgData.AccessLogPath); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logger := utils.GetLogger()
	defer func(logger *utils.Logger) {
		_ = logger.Close()
	}(logger)
	fmt.Println("Synchronizing Artica Cores version index...")
	syncer := sync.NewSyncer(cfg, logger, nil)
	syncer.SyncArticaCores()
	fmt.Println("\nArtica Cores sync completed")
	fmt.Printf("Index saved to: %s/artica/indexes/core.json\n", cfgData.RepositoryPath)
}

// handleArticaCleanup nettoie les anciennes versions des packages
func handleArticaCleanup(args []string) {
	keepVersions := 2
	if len(args) >= 2 {
		fmt.Sscanf(args[1], "%d", &keepVersions)
	}

	fmt.Printf("Cleaning up old .deb packages (keeping %d versions)...\n", keepVersions)

	// Lister tous les répertoires de produits
	entries, err := os.ReadDir(articarepos.ArticaDebBasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read deb directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			productCode := entry.Name()
			if err := articarepos.CleanupOldDebPackages(productCode, keepVersions); err != nil {
				fmt.Printf("  %s: FAILED - %v\n", productCode, err)
			} else {
				fmt.Printf("  %s: cleaned\n", productCode)
			}
		}
	}

	fmt.Println("Cleanup completed")
}

// downloadIndex télécharge un index Artica (version simple pour CLI)
func downloadIndex(indexURL string) (string, error) {
	// Utiliser wget ou curl si disponible
	cmd := fmt.Sprintf("curl -s '%s' 2>/dev/null || wget -qO- '%s' 2>/dev/null", indexURL, indexURL)

	output, err := runCommand("sh", "-c", cmd)
	if err != nil {
		return "", fmt.Errorf("failed to download index: %w", err)
	}

	return output, nil
}

// downloadPackage télécharge un package Artica (version simple pour CLI)
func downloadPackage(soft articarepos.ArticaSoft) error {
	// Créer le répertoire
	if err := os.MkdirAll(soft.TempDir, 0755); err != nil {
		return err
	}

	// Télécharger avec curl ou wget
	cmd := fmt.Sprintf("curl -s -o '%s' '%s' 2>/dev/null || wget -qO '%s' '%s' 2>/dev/null",
		soft.Tempfile, soft.Url, soft.Tempfile, soft.Url)

	_, err := runCommand("sh", "-c", cmd)
	return err
}

// verifyFile vérifie un fichier (version simple pour CLI)
func verifyFile(path, expectedMD5 string, expectedSize int64) (bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	if stat.Size() != expectedSize {
		return false, nil
	}

	// Vérifier MD5 avec md5sum
	output, err := runCommand("md5sum", path)
	if err != nil {
		return false, err
	}

	parts := strings.Fields(output)
	if len(parts) < 1 {
		return false, fmt.Errorf("invalid md5sum output")
	}

	return strings.EqualFold(parts[0], expectedMD5), nil
}

// runCommand exécute une commande et retourne sa sortie
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	return string(output), err
}

// printArticaHelp affiche l'aide pour les commandes artica
func printArticaHelp() {
	fmt.Printf("%s v%s - Artica Package Management\n\n", AppName, version)
	fmt.Println("Usage:")
	fmt.Println("  activedebiansync artica <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  build <product-code> <version> <tar.gz-path>")
	fmt.Println("      Build a .deb package from a tar.gz source")
	fmt.Println()
	fmt.Println("  build-all [release]")
	fmt.Println("      Build all packages from downloaded sources (default: bookworm)")
	fmt.Println()
	fmt.Println("  install <product-code>")
	fmt.Println("      Install an Artica package (calls artica-phpfpm-service -install-deb)")
	fmt.Println()
	fmt.Println("  remove <product-code>")
	fmt.Println("      Remove an Artica package (calls artica-phpfpm-service -remove-deb)")
	fmt.Println()
	fmt.Println("  list")
	fmt.Println("      List all available Artica .deb packages")
	fmt.Println()
	fmt.Println("  info <product-code>")
	fmt.Println("      Show information about an Artica package")
	fmt.Println()
	fmt.Println("  sync")
	fmt.Println("      Sync Artica repositories and build .deb packages")
	fmt.Println()
	fmt.Println("  sync-cores")
	fmt.Println("      Sync Artica Cores version index (downloads core.json)")
	fmt.Println()
	fmt.Println("  cleanup [keep-versions]")
	fmt.Println("      Clean up old package versions (default: keep 2)")
	fmt.Println()
	fmt.Println("Package Structure:")
	fmt.Printf("  .deb files are stored in: %s\n", articarepos.ArticaDebBasePath)
	fmt.Printf("  Content is extracted to: %s/<product-code>/\n", articarepos.ArticaDebBasePath)
	fmt.Println()
	fmt.Println("Install/Remove Scripts:")
	fmt.Printf("  Install: %s -install-deb <product-code>\n", articarepos.ArticaServicePath)
	fmt.Printf("  Remove:  %s -remove-deb <product-code>\n", articarepos.ArticaServicePath)
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Build a package manually")
	fmt.Println("  activedebiansync artica build APP_NGINX 1.2.3 /tmp/nginx.tar.gz")
	fmt.Println()
	fmt.Println("  # Sync all Artica packages")
	fmt.Println("  activedebiansync artica sync")
	fmt.Println()
	fmt.Println("  # Sync Artica Cores version index")
	fmt.Println("  activedebiansync artica sync-cores")
	fmt.Println()
	fmt.Println("  # List available packages")
	fmt.Println("  activedebiansync artica list")
	fmt.Println()
	fmt.Println("  # Install a package")
	fmt.Println("  activedebiansync artica install APP_NGINX")
	fmt.Println()
	fmt.Println("  # Remove a package")
	fmt.Println("  activedebiansync artica remove APP_NGINX")
}
