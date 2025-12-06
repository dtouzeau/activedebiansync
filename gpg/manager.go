package gpg

import (
	"activedebiansync/config"
	"activedebiansync/utils"
	"bytes"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// GPGManager gère la signature GPG des dépôts
type GPGManager struct {
	config     *config.Config
	logger     *utils.Logger
	privateKey *openpgp.Entity
	keyLoaded  bool
}

// NewGPGManager crée une nouvelle instance de GPGManager
func NewGPGManager(cfg *config.Config, logger *utils.Logger) *GPGManager {
	return &GPGManager{
		config:    cfg,
		logger:    logger,
		keyLoaded: false,
	}
}

// GetConfig retourne la configuration
func (gm *GPGManager) GetConfig() *config.Config {
	return gm.config
}

// GenerateKey génère une nouvelle paire de clés GPG
func (gm *GPGManager) GenerateKey(name, comment, email string) error {
	gm.logger.LogInfo("Generating GPG key pair for %s <%s>", name, email)

	cfg := gm.config.Get()

	// Configuration pour la génération de clé
	zconfig := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 6,
		},
		RSABits: 4096,
	}

	// Générer l'entité (clé)
	entity, err := openpgp.NewEntity(name, comment, email, zconfig)
	if err != nil {
		return fmt.Errorf("failed to create entity: %w", err)
	}

	// Créer le répertoire GPG si nécessaire
	gpgDir := filepath.Dir(cfg.GPGPrivateKeyPath)
	if err := os.MkdirAll(gpgDir, 0700); err != nil {
		return fmt.Errorf("failed to create GPG directory: %w", err)
	}

	// Sauvegarder la clé privée
	privFile, err := os.OpenFile(cfg.GPGPrivateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	privWriter, err := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armor encoder: %w", err)
	}

	if err := entity.SerializePrivate(privWriter, nil); err != nil {
		privWriter.Close()
		return fmt.Errorf("failed to serialize private key: %w", err)
	}
	privWriter.Close()

	gm.logger.LogInfo("Private key saved to: %s", cfg.GPGPrivateKeyPath)

	// Sauvegarder la clé publique
	pubFile, err := os.OpenFile(cfg.GPGPublicKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	pubWriter, err := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armor encoder: %w", err)
	}

	if err := entity.Serialize(pubWriter); err != nil {
		pubWriter.Close()
		return fmt.Errorf("failed to serialize public key: %w", err)
	}
	pubWriter.Close()

	gm.logger.LogInfo("Public key saved to: %s", cfg.GPGPublicKeyPath)

	// Charger la clé générée
	gm.privateKey = entity
	gm.keyLoaded = true

	// Obtenir l'empreinte de la clé
	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	gm.logger.LogInfo("GPG Key fingerprint: %s", fingerprint)

	return nil
}

// LoadKey charge la clé privée depuis le fichier
func (gm *GPGManager) LoadKey() error {
	cfg := gm.config.Get()

	if !cfg.GPGSigningEnabled {
		return nil // Signature désactivée
	}

	// Vérifier que le fichier existe
	if _, err := os.Stat(cfg.GPGPrivateKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key file not found: %s (run 'activedebiansync gpg init')", cfg.GPGPrivateKeyPath)
	}

	// Lire le fichier de clé
	keyFile, err := os.Open(cfg.GPGPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open private key: %w", err)
	}
	defer keyFile.Close()

	// Décoder l'armor
	block, err := armor.Decode(keyFile)
	if err != nil {
		return fmt.Errorf("failed to decode armored key: %w", err)
	}

	// Lire l'entité
	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return fmt.Errorf("failed to read key ring: %w", err)
	}

	if len(entityList) == 0 {
		return fmt.Errorf("no keys found in key file")
	}

	gm.privateKey = entityList[0]
	gm.keyLoaded = true

	fingerprint := fmt.Sprintf("%X", gm.privateKey.PrimaryKey.Fingerprint)
	gm.logger.LogInfo("GPG key loaded successfully (fingerprint: %s)", fingerprint)

	return nil
}

// SignFile signe un fichier et crée un fichier .gpg détaché
func (gm *GPGManager) SignFile(filePath string) error {
	if !gm.keyLoaded {
		if err := gm.LoadKey(); err != nil {
			return err
		}
	}

	// Lire le fichier à signer
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Créer la signature détachée
	var sigBuf bytes.Buffer
	err = openpgp.ArmoredDetachSign(&sigBuf, gm.privateKey, bytes.NewReader(content), nil)
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	// Écrire la signature
	sigPath := filePath + ".gpg"
	if err := os.WriteFile(sigPath, sigBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	return nil
}

// SignReleaseFile signe un fichier Release et crée Release.gpg + InRelease
func (gm *GPGManager) SignReleaseFile(releaseFilePath string) error {
	cfg := gm.config.Get()

	if !cfg.GPGSigningEnabled {
		gm.logger.LogInfo("GPG signing is disabled, skipping signature")
		return nil
	}

	if !gm.keyLoaded {
		if err := gm.LoadKey(); err != nil {
			return err
		}
	}

	gm.logger.LogInfo("Signing Release file: %s", releaseFilePath)

	// Lire le contenu du Release
	releaseContent, err := os.ReadFile(releaseFilePath)
	if err != nil {
		return fmt.Errorf("failed to read Release file: %w", err)
	}

	// 1. Créer Release.gpg (signature détachée)
	var detachedSig bytes.Buffer
	err = openpgp.ArmoredDetachSign(&detachedSig, gm.privateKey, bytes.NewReader(releaseContent), nil)
	if err != nil {
		return fmt.Errorf("failed to create detached signature: %w", err)
	}

	releaseGpgPath := releaseFilePath + ".gpg"
	if err := os.WriteFile(releaseGpgPath, detachedSig.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write Release.gpg: %w", err)
	}
	gm.logger.LogInfo("Created: %s", releaseGpgPath)

	// 2. Créer InRelease (clearsign)
	var inRelease bytes.Buffer
	err = openpgp.ArmoredDetachSign(&inRelease, gm.privateKey, bytes.NewReader(releaseContent), &packet.Config{
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to create inline signature: %w", err)
	}

	// Pour InRelease, on doit créer un format clearsigned
	// Créer le fichier InRelease avec le contenu + signature
	inReleasePath := filepath.Join(filepath.Dir(releaseFilePath), "InRelease")
	inReleaseFile, err := os.Create(inReleasePath)
	if err != nil {
		return fmt.Errorf("failed to create InRelease: %w", err)
	}
	defer inReleaseFile.Close()

	// Écrire le clearsign
	writer, err := armor.Encode(inReleaseFile, "PGP SIGNED MESSAGE", map[string]string{
		"Hash": "SHA256",
	})
	if err != nil {
		return fmt.Errorf("failed to create armor writer: %w", err)
	}

	if _, err := writer.Write(releaseContent); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write content: %w", err)
	}
	writer.Close()

	// Ajouter la signature
	if _, err := inReleaseFile.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	if _, err := inReleaseFile.Write(detachedSig.Bytes()); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	gm.logger.LogInfo("Created: %s", inReleasePath)

	return nil
}

// SignAllReleaseFiles signe tous les fichiers Release du dépôt
func (gm *GPGManager) SignAllReleaseFiles() error {
	cfg := gm.config.Get()

	if !cfg.GPGSigningEnabled {
		return nil
	}

	gm.logger.LogInfo("Signing all Release files in repository")

	distsPath := filepath.Join(cfg.RepositoryPath, "dists")
	var signedCount int

	err := filepath.Walk(distsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Chercher les fichiers nommés "Release" (pas Release.gpg ou InRelease)
		if !info.IsDir() && info.Name() == "Release" {
			if err := gm.SignReleaseFile(path); err != nil {
				gm.logger.LogError("Failed to sign %s: %v", path, err)
				return err
			}
			signedCount++
		}

		return nil
	})

	if err != nil {
		return err
	}

	gm.logger.LogInfo("Successfully signed %d Release files", signedCount)
	return nil
}

// ExportPublicKey exporte la clé publique au format texte
func (gm *GPGManager) ExportPublicKey(outputPath string) error {
	cfg := gm.config.Get()

	// Lire la clé publique
	pubKeyContent, err := os.ReadFile(cfg.GPGPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	// Si outputPath est "-", écrire sur stdout
	if outputPath == "-" {
		fmt.Println(string(pubKeyContent))
		return nil
	}

	// Sinon, écrire dans le fichier
	if err := os.WriteFile(outputPath, pubKeyContent, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	gm.logger.LogInfo("Public key exported to: %s", outputPath)
	return nil
}

// GetKeyInfo retourne les informations sur la clé chargée
func (gm *GPGManager) GetKeyInfo() (map[string]string, error) {
	if !gm.keyLoaded {
		if err := gm.LoadKey(); err != nil {
			return nil, err
		}
	}

	info := make(map[string]string)

	// Identité primaire
	for _, ident := range gm.privateKey.Identities {
		info["name"] = ident.UserId.Name
		info["email"] = ident.UserId.Email
		info["comment"] = ident.UserId.Comment
		break
	}

	// Empreinte
	info["fingerprint"] = fmt.Sprintf("%X", gm.privateKey.PrimaryKey.Fingerprint)

	// ID de clé (derniers 8 octets de l'empreinte)
	fingerprint := gm.privateKey.PrimaryKey.Fingerprint
	info["keyid"] = fmt.Sprintf("%X", fingerprint[len(fingerprint)-8:])

	// Date de création
	info["created"] = gm.privateKey.PrimaryKey.CreationTime.Format(time.RFC3339)

	// Algorithme
	info["algorithm"] = "RSA"
	info["bits"] = "4096"

	return info, nil
}

// IsEnabled retourne true si la signature GPG est activée
func (gm *GPGManager) IsEnabled() bool {
	cfg := gm.config.Get()
	return cfg.GPGSigningEnabled
}

// GetPublicKeyPath retourne le chemin de la clé publique
func (gm *GPGManager) GetPublicKeyPath() string {
	cfg := gm.config.Get()
	return cfg.GPGPublicKeyPath
}

// GetPublicKeyForWeb retourne la clé publique pour distribution web
func (gm *GPGManager) GetPublicKeyForWeb() (string, error) {
	cfg := gm.config.Get()

	content, err := os.ReadFile(cfg.GPGPublicKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key: %w", err)
	}

	return string(content), nil
}

// GenerateClientInstructions génère les instructions pour les clients
func (gm *GPGManager) GenerateClientInstructions(serverURL string) string {
	cfg := gm.config.Get()

	var sb strings.Builder

	sb.WriteString("# Instructions for APT clients\n\n")
	sb.WriteString("## 1. Import the GPG key\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString(fmt.Sprintf("curl -fsSL %s/gpg-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/activedebiansync.gpg\n", serverURL))
	sb.WriteString("```\n\n")

	sb.WriteString("## 2. Add the repository\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("echo \"deb [signed-by=/usr/share/keyrings/activedebiansync.gpg] ")
	sb.WriteString(fmt.Sprintf("%s/debian ", serverURL))

	if len(cfg.DebianReleases) > 0 {
		sb.WriteString(cfg.DebianReleases[0])
	} else {
		sb.WriteString("bookworm")
	}

	sb.WriteString(" ")
	if len(cfg.DebianComponents) > 0 {
		sb.WriteString(strings.Join(cfg.DebianComponents, " "))
	} else {
		sb.WriteString("main")
	}

	sb.WriteString("\" | sudo tee /etc/apt/sources.list.d/activedebiansync.list\n")
	sb.WriteString("```\n\n")

	sb.WriteString("## 3. Update package list\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("sudo apt update\n")
	sb.WriteString("```\n")

	return sb.String()
}

// InitializeOrLoadKey initialise automatiquement une clé GPG si elle n'existe pas, sinon la charge
// Retourne true si une nouvelle clé a été générée, false si elle a été chargée
func (gm *GPGManager) InitializeOrLoadKey() (bool, error) {
	cfg := gm.config.Get()

	if !cfg.GPGSigningEnabled {
		return false, nil
	}

	// Vérifier si les clés existent
	privateKeyExists := true
	publicKeyExists := true

	if _, err := os.Stat(cfg.GPGPrivateKeyPath); os.IsNotExist(err) {
		privateKeyExists = false
	}
	if _, err := os.Stat(cfg.GPGPublicKeyPath); os.IsNotExist(err) {
		publicKeyExists = false
	}

	// Si les deux clés existent, les charger
	if privateKeyExists && publicKeyExists {
		if err := gm.LoadKey(); err != nil {
			return false, fmt.Errorf("failed to load existing GPG key: %w", err)
		}
		return false, nil
	}

	// Si aucune clé n'existe, générer une nouvelle paire
	if !privateKeyExists && !publicKeyExists {
		gm.logger.LogInfo("GPG keys not found, generating new key pair...")

		name := cfg.GPGKeyName
		if name == "" {
			name = "ActiveDebianSync Repository"
		}
		email := cfg.GPGKeyEmail
		if email == "" {
			email = "repo@activedebiansync.local"
		}
		comment := cfg.GPGKeyComment
		if comment == "" {
			comment = "Automatic repository signing key"
		}

		if err := gm.GenerateKey(name, comment, email); err != nil {
			return false, fmt.Errorf("failed to generate GPG key: %w", err)
		}

		gm.logger.LogInfo("GPG key pair generated successfully")
		return true, nil
	}

	// Situation incohérente: une seule clé existe
	if privateKeyExists && !publicKeyExists {
		return false, fmt.Errorf("private key exists but public key is missing at %s", cfg.GPGPublicKeyPath)
	}
	return false, fmt.Errorf("public key exists but private key is missing at %s", cfg.GPGPrivateKeyPath)
}

// KeyExists vérifie si les clés GPG existent
func (gm *GPGManager) KeyExists() bool {
	cfg := gm.config.Get()

	_, errPriv := os.Stat(cfg.GPGPrivateKeyPath)
	_, errPub := os.Stat(cfg.GPGPublicKeyPath)

	return errPriv == nil && errPub == nil
}

// IsLoaded retourne true si la clé est chargée en mémoire
func (gm *GPGManager) IsLoaded() bool {
	return gm.keyLoaded
}
