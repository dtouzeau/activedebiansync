package main

import (
	"activedebiansync/config"
	"activedebiansync/gpg"
	pkgmanager "activedebiansync/package"
	"activedebiansync/utils"
	"flag"
	"fmt"
	"os"
)

// handlePackageCommand gère les commandes de gestion des packages
func handlePackageCommand() {
	if len(os.Args) < 3 {
		printPackageHelp()
		os.Exit(1)
	}

	packageCmd := flag.NewFlagSet("package", flag.ExitOnError)
	configPath := packageCmd.String("config", config.DefaultConfigPath, "Path to configuration file")

	// Parse les flags après la sous-commande
	packageCmd.Parse(os.Args[2:])

	// Charger la configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialiser le logger en mode console simple
	logger := &utils.Logger{}

	// Créer le GPG manager
	gpgManager := gpg.NewGPGManager(cfg, logger)

	// Charger la clé GPG si activée
	cfgData := cfg.Get()
	if cfgData.GPGSigningEnabled {
		if err := gpgManager.LoadKey(); err != nil {
			// Continuer sans GPG si la clé n'existe pas
			logger.LogInfo("GPG key not loaded: %v", err)
		}
	}

	// Créer le package manager
	pkgManager := pkgmanager.NewPackageManager(cfg, logger, gpgManager)

	// Récupérer la sous-commande
	action := packageCmd.Arg(0)

	switch action {
	case "add":
		handlePackageAdd(pkgManager, packageCmd.Args())
	case "remove":
		handlePackageRemove(pkgManager, packageCmd.Args())
	case "list":
		handlePackageList(pkgManager, packageCmd.Args())
	case "regenerate":
		handlePackageRegenerate(pkgManager, packageCmd.Args())
	default:
		fmt.Fprintf(os.Stderr, "Unknown package command: %s\n", action)
		printPackageHelp()
		os.Exit(1)
	}
}

// handlePackageAdd ajoute un package
func handlePackageAdd(pm *pkgmanager.PackageManager, args []string) {
	if len(args) < 5 {
		fmt.Println("Usage: activedebiansync package add <deb-file> <release> <component> <architecture>")
		fmt.Println("Example: activedebiansync package add myapp_1.0.0_amd64.deb bookworm main amd64")
		os.Exit(1)
	}

	debFile := args[1]
	release := args[2]
	component := args[3]
	architecture := args[4]

	fmt.Printf("Adding package: %s\n", debFile)
	fmt.Printf("Target: %s/%s/%s\n", release, component, architecture)

	if err := pm.AddPackage(debFile, release, component, architecture); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add package: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Package added successfully")
	fmt.Println("✓ Indexes regenerated")
}

// handlePackageRemove supprime un package
func handlePackageRemove(pm *pkgmanager.PackageManager, args []string) {
	if len(args) < 6 {
		fmt.Println("Usage: activedebiansync package remove <package-name> <version> <release> <component> <architecture>")
		fmt.Println("Example: activedebiansync package remove myapp 1.0.0 bookworm main amd64")
		os.Exit(1)
	}

	packageName := args[1]
	version := args[2]
	release := args[3]
	component := args[4]
	architecture := args[5]

	fmt.Printf("Removing package: %s %s\n", packageName, version)
	fmt.Printf("From: %s/%s/%s\n", release, component, architecture)

	if err := pm.RemovePackage(packageName, version, release, component, architecture); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove package: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Package removed successfully")
	fmt.Println("✓ Indexes regenerated")
}

// handlePackageList liste les packages
func handlePackageList(pm *pkgmanager.PackageManager, args []string) {
	if len(args) < 4 {
		fmt.Println("Usage: activedebiansync package list <release> <component> <architecture>")
		fmt.Println("Example: activedebiansync package list bookworm main amd64")
		os.Exit(1)
	}

	release := args[1]
	component := args[2]
	architecture := args[3]

	fmt.Printf("Listing packages for: %s/%s/%s\n\n", release, component, architecture)

	packages, err := pm.ListPackages(release, component, architecture)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list packages: %v\n", err)
		os.Exit(1)
	}

	if len(packages) == 0 {
		fmt.Println("No custom packages found")
		return
	}

	fmt.Printf("Found %d package(s):\n\n", len(packages))
	for _, pkg := range packages {
		fmt.Printf("Package: %s\n", pkg.Package)
		fmt.Printf("  Version: %s\n", pkg.Version)
		fmt.Printf("  Architecture: %s\n", pkg.Architecture)
		fmt.Printf("  Size: %d bytes\n", pkg.Size)
		if pkg.Description != "" {
			fmt.Printf("  Description: %s\n", pkg.Description)
		}
		fmt.Println()
	}
}

// handlePackageRegenerate régénère les indexes
func handlePackageRegenerate(pm *pkgmanager.PackageManager, args []string) {
	if len(args) < 4 {
		fmt.Println("Usage: activedebiansync package regenerate <release> <component> <architecture>")
		fmt.Println("Example: activedebiansync package regenerate bookworm main amd64")
		os.Exit(1)
	}

	release := args[1]
	component := args[2]
	architecture := args[3]

	fmt.Printf("Regenerating indexes for: %s/%s/%s\n", release, component, architecture)

	if err := pm.RegenerateIndexes(release, component, architecture); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to regenerate indexes: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Indexes regenerated successfully")
}

// printPackageHelp affiche l'aide pour les commandes package
func printPackageHelp() {
	fmt.Printf("%s v%s - Package Management\n\n", AppName, version)
	fmt.Println("Usage:")
	fmt.Println("  activedebiansync package <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  add <deb-file> <release> <component> <architecture>")
	fmt.Println("      Add a custom .deb package to the repository")
	fmt.Println()
	fmt.Println("  remove <package-name> <version> <release> <component> <architecture>")
	fmt.Println("      Remove a package from the repository")
	fmt.Println()
	fmt.Println("  list <release> <component> <architecture>")
	fmt.Println("      List all custom packages")
	fmt.Println()
	fmt.Println("  regenerate <release> <component> <architecture>")
	fmt.Println("      Regenerate package indexes")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Add a custom package")
	fmt.Println("  activedebiansync package add myapp_1.0.0_amd64.deb bookworm main amd64")
	fmt.Println()
	fmt.Println("  # List packages")
	fmt.Println("  activedebiansync package list bookworm main amd64")
	fmt.Println()
	fmt.Println("  # Remove a package")
	fmt.Println("  activedebiansync package remove myapp 1.0.0 bookworm main amd64")
	fmt.Println()
	fmt.Println("  # Regenerate indexes")
	fmt.Println("  activedebiansync package regenerate bookworm main amd64")
}
