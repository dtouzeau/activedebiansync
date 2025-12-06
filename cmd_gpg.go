package main

import (
	"activedebiansync/config"
	"activedebiansync/gpg"
	"activedebiansync/utils"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// handleGPGCommand gère les commandes GPG
func handleGPGCommand() {
	if len(os.Args) < 3 {
		printGPGHelp()
		os.Exit(1)
	}

	gpgCmd := flag.NewFlagSet("gpg", flag.ExitOnError)
	configPath := gpgCmd.String("config", config.DefaultConfigPath, "Path to configuration file")

	// Parse les flags après la sous-commande
	gpgCmd.Parse(os.Args[2:])

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

	// Récupérer la sous-commande
	action := gpgCmd.Arg(0)

	switch action {
	case "init":
		handleGPGInit(gpgManager, gpgCmd.Args())
	case "export-key":
		handleGPGExportKey(gpgManager, gpgCmd.Args())
	case "sign":
		handleGPGSign(gpgManager, gpgCmd.Args())
	case "info":
		handleGPGInfo(gpgManager)
	default:
		fmt.Fprintf(os.Stderr, "Unknown GPG command: %s\n", action)
		printGPGHelp()
		os.Exit(1)
	}
}

// handleGPGInit initialise une nouvelle paire de clés GPG
func handleGPGInit(gm *gpg.GPGManager, args []string) {
	cfg := gm.GetConfig().Get()

	// Vérifier si les clés existent déjà
	if _, err := os.Stat(cfg.GPGPrivateKeyPath); err == nil {
		fmt.Printf("⚠️  GPG keys already exist at:\n")
		fmt.Printf("   Private: %s\n", cfg.GPGPrivateKeyPath)
		fmt.Printf("   Public:  %s\n", cfg.GPGPublicKeyPath)
		fmt.Printf("\n")
		fmt.Printf("To regenerate keys, first delete the existing ones:\n")
		fmt.Printf("  rm %s\n", cfg.GPGPrivateKeyPath)
		fmt.Printf("  rm %s\n", cfg.GPGPublicKeyPath)
		os.Exit(1)
	}

	fmt.Println("🔐 Initializing GPG keys for repository signing")
	fmt.Println()

	// Utiliser les valeurs de la config
	name := cfg.GPGKeyName
	email := cfg.GPGKeyEmail
	comment := cfg.GPGKeyComment

	fmt.Printf("Key details:\n")
	fmt.Printf("  Name:    %s\n", name)
	fmt.Printf("  Email:   %s\n", email)
	fmt.Printf("  Comment: %s\n", comment)
	fmt.Println()

	fmt.Println("Generating 4096-bit RSA key pair (this may take a minute)...")

	if err := gm.GenerateKey(name, comment, email); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to generate GPG keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ GPG keys generated successfully!")
	fmt.Println()

	// Afficher les informations de la clé
	info, err := gm.GetKeyInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not retrieve key info: %v\n", err)
	} else {
		fmt.Printf("Key Information:\n")
		fmt.Printf("  Fingerprint: %s\n", info["fingerprint"])
		fmt.Printf("  Key ID:      %s\n", info["keyid"])
		fmt.Printf("  Created:     %s\n", info["created"])
		fmt.Println()
	}

	fmt.Printf("Keys saved to:\n")
	fmt.Printf("  Private: %s\n", cfg.GPGPrivateKeyPath)
	fmt.Printf("  Public:  %s\n", cfg.GPGPublicKeyPath)
	fmt.Println()

	// Instructions de configuration
	fmt.Println("📝 Next steps:")
	fmt.Println()
	fmt.Println("1. Enable GPG signing in configuration:")
	fmt.Printf("   Edit: %s\n", config.DefaultConfigPath)
	fmt.Println("   Set: \"gpg_signing_enabled\": true")
	fmt.Println()
	fmt.Println("2. Export the public key for clients:")
	fmt.Println("   activedebiansync gpg export-key /var/www/html/gpg-key.asc")
	fmt.Println()
	fmt.Println("3. Sign all existing Release files:")
	fmt.Println("   activedebiansync gpg sign")
	fmt.Println()
	fmt.Println("4. Restart the daemon:")
	fmt.Println("   systemctl restart activedebiansync")
	fmt.Println()
}

// handleGPGExportKey exporte la clé publique
func handleGPGExportKey(gm *gpg.GPGManager, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: activedebiansync gpg export-key <output-file>")
		fmt.Println("       activedebiansync gpg export-key -  (stdout)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  activedebiansync gpg export-key /var/www/html/gpg-key.asc")
		fmt.Println("  activedebiansync gpg export-key - | cat")
		os.Exit(1)
	}

	outputPath := args[1]

	if outputPath != "-" {
		fmt.Printf("Exporting public key to: %s\n", outputPath)
	}

	if err := gm.ExportPublicKey(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to export public key: %v\n", err)
		os.Exit(1)
	}

	if outputPath != "-" {
		fmt.Println("✓ Public key exported successfully")
		fmt.Println()
		fmt.Println("📋 Client instructions:")
		fmt.Println()
		fmt.Println("Clients should import the key with:")
		fmt.Printf("  curl -fsSL http://your-server/%s | sudo gpg --dearmor -o /usr/share/keyrings/activedebiansync.gpg\n", filepath.Base(outputPath))
		fmt.Println()
	}
}

// handleGPGSign signe tous les fichiers Release du dépôt
func handleGPGSign(gm *gpg.GPGManager, args []string) {
	cfg := gm.GetConfig().Get()

	if !cfg.GPGSigningEnabled {
		fmt.Println("⚠️  GPG signing is disabled in configuration")
		fmt.Printf("   Edit: %s\n", config.DefaultConfigPath)
		fmt.Println("   Set: \"gpg_signing_enabled\": true")
		os.Exit(1)
	}

	fmt.Println("🔏 Signing all Release files in repository...")

	if err := gm.SignAllReleaseFiles(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign Release files: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ All Release files signed successfully")
}

// handleGPGInfo affiche les informations sur la clé
func handleGPGInfo(gm *gpg.GPGManager) {
	cfg := gm.GetConfig().Get()

	fmt.Println("GPG Configuration:")
	fmt.Printf("  Signing enabled: %v\n", cfg.GPGSigningEnabled)
	fmt.Printf("  Private key:     %s\n", cfg.GPGPrivateKeyPath)
	fmt.Printf("  Public key:      %s\n", cfg.GPGPublicKeyPath)
	fmt.Println()

	// Vérifier si les clés existent
	if _, err := os.Stat(cfg.GPGPrivateKeyPath); os.IsNotExist(err) {
		fmt.Println("❌ No GPG keys found")
		fmt.Println()
		fmt.Println("Initialize keys with:")
		fmt.Println("  activedebiansync gpg init")
		return
	}

	// Charger et afficher les informations
	info, err := gm.GetKeyInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load key info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Key Information:")
	fmt.Printf("  Name:        %s\n", info["name"])
	fmt.Printf("  Email:       %s\n", info["email"])
	if info["comment"] != "" {
		fmt.Printf("  Comment:     %s\n", info["comment"])
	}
	fmt.Printf("  Fingerprint: %s\n", info["fingerprint"])
	fmt.Printf("  Key ID:      %s\n", info["keyid"])
	fmt.Printf("  Algorithm:   %s %s-bit\n", info["algorithm"], info["bits"])
	fmt.Printf("  Created:     %s\n", info["created"])
	fmt.Println()
}

// printGPGHelp affiche l'aide pour les commandes GPG
func printGPGHelp() {
	fmt.Printf("%s v%s - GPG Management\n\n", AppName, version)
	fmt.Println("Usage:")
	fmt.Println("  activedebiansync gpg <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init")
	fmt.Println("      Generate a new GPG key pair for repository signing")
	fmt.Println()
	fmt.Println("  export-key <output-file>")
	fmt.Println("      Export the public key for distribution to clients")
	fmt.Println()
	fmt.Println("  sign")
	fmt.Println("      Sign all Release files in the repository")
	fmt.Println()
	fmt.Println("  info")
	fmt.Println("      Display information about the GPG key")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Initialize GPG keys")
	fmt.Println("  activedebiansync gpg init")
	fmt.Println()
	fmt.Println("  # Export public key for web distribution")
	fmt.Println("  activedebiansync gpg export-key /var/www/html/gpg-key.asc")
	fmt.Println()
	fmt.Println("  # Export to stdout")
	fmt.Println("  activedebiansync gpg export-key -")
	fmt.Println()
	fmt.Println("  # Sign all Release files")
	fmt.Println("  activedebiansync gpg sign")
	fmt.Println()
	fmt.Println("  # Show key information")
	fmt.Println("  activedebiansync gpg info")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  Edit /etc/ActiveDebianSync/config.json:")
	fmt.Println("  {")
	fmt.Println("    \"gpg_signing_enabled\": true,")
	fmt.Println("    \"gpg_key_name\": \"Your Repository Name\",")
	fmt.Println("    \"gpg_key_email\": \"repo@your-domain.com\"")
	fmt.Println("  }")
}
