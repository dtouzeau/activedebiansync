package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultConfigPath = "/etc/ActiveDebianSync/config.json"
)

// ReleaseConfig represents configuration for a specific Debian release
type ReleaseConfig struct {
	Name           string   `json:"name"`                      // Release name: "buster", "bookworm", etc.
	Mirror         string   `json:"mirror"`                    // Mirror URL for this release (overrides default)
	SecurityMirror string   `json:"security_mirror,omitempty"` // Security mirror URL (for archive: http://archive.debian.org/debian-security)
	SecuritySuite  string   `json:"security_suite,omitempty"`  // Security suite path (for archive: "buster/updates", for current: "bookworm-security")
	IsArchived     bool     `json:"is_archived"`               // True if release is archived (uses archive.debian.org)
	SyncUpdates    bool     `json:"sync_updates"`              // Sync -updates suite
	SyncBackports  bool     `json:"sync_backports"`            // Sync -backports suite
	SyncSecurity   bool     `json:"sync_security"`             // Sync security updates
	Components     []string `json:"components,omitempty"`      // Override components for this release (e.g., no non-free-firmware for old releases)
}

// Config représente la configuration complète du démon
type Config struct {
	// Paramètres de synchronisation
	SyncInterval         int             `json:"sync_interval"`          // En minutes
	RepositoryPath       string          `json:"repository_path"`        // Chemin local du miroir
	DebianMirror         string          `json:"debian_mirror"`          // URL du miroir source (default)
	DebianReleases       []string        `json:"debian_releases"`        // ["bookworm", "trixie"] - simple release list
	DebianArchs          []string        `json:"debian_architectures"`   // ["amd64", "arm64"]
	DebianComponents     []string        `json:"debian_components"`      // ["main", "contrib", "non-free", "non-free-firmware"]
	ReleaseConfigs       []ReleaseConfig `json:"release_configs"`        // Advanced per-release configuration (optional)
	SyncPackages         bool            `json:"sync_packages"`          // Télécharger les packages .deb (pas seulement les métadonnées)
	SyncContents         bool            `json:"sync_contents"`          // Télécharger les fichiers Contents pour la recherche (comme apt-file)
	PackageSearchEnabled bool            `json:"package_search_enabled"` // Activer la recherche de packages
	ConfigPath           string          `json:"config_path"`

	// Paramètres debian-installer (pour build-simple-cdd, netboot, etc.)
	SyncDebianInstaller bool     `json:"sync_debian_installer"` // Activer la synchronisation debian-installer
	SyncInstallerUdebs  bool     `json:"sync_installer_udebs"`  // Télécharger les udebs (micro-packages pour l'installateur)
	SyncInstallerImages bool     `json:"sync_installer_images"` // Télécharger les images d'installation (netboot, hd-media, cdrom)
	InstallerImageTypes []string `json:"installer_image_types"` // Types d'images à télécharger ["netboot", "hd-media", "cdrom"]

	// Paramètres avancés de synchronisation
	MaxConcurrentDownloads  int    `json:"max_concurrent_downloads"`   // Nombre de téléchargements parallèles (défaut: 4)
	DownloadBandwidthLimit  int    `json:"download_bandwidth_limit"`   // Limite en KB/s (0 = illimité)
	BlockClientsDuringSync  bool   `json:"block_clients_during_sync"`  // Bloquer l'accès HTTP pendant la sync
	SyncAllowedHoursEnabled bool   `json:"sync_allowed_hours_enabled"` // Activer la restriction horaire
	SyncAllowedHoursStart   string `json:"sync_allowed_hours_start"`   // Heure de début (format "HH:MM")
	SyncAllowedHoursEnd     string `json:"sync_allowed_hours_end"`     // Heure de fin (format "HH:MM")

	// Paramètres serveur HTTP/HTTPS
	HTTPEnabled  bool   `json:"http_enabled"`
	HTTPPort     int    `json:"http_port"`
	HTTPSEnabled bool   `json:"https_enabled"`
	HTTPSPort    int    `json:"https_port"`
	TLSCertFile  string `json:"tls_cert_file"`
	TLSKeyFile   string `json:"tls_key_file"`

	// Paramètres REST API
	APIEnabled    bool     `json:"api_enabled"`
	APIPort       int      `json:"api_port"`
	APIListenAddr string   `json:"api_listen_addr"` // "127.0.0.1" ou "0.0.0.0"
	APIAllowedIPs []string `json:"api_allowed_ips"` // Liste d'IPs autorisées

	// Paramètres de stockage
	MaxDiskUsagePercent int `json:"max_disk_usage_percent"` // Défaut: 90%

	// Paramètres de logging
	LogPath       string `json:"log_path"`
	AccessLogPath string `json:"access_log_path"`
	PIDFile       string `json:"pid_file"`
	SystemID      string `json:"system_id"` //Unique identifier

	// Paramètres d'exécution
	RunAsUser  string `json:"run_as_user"`  // Utilisateur Unix (optionnel)
	RunAsGroup string `json:"run_as_group"` // Groupe Unix (optionnel)

	// Paramètres GPG
	GPGSigningEnabled bool   `json:"gpg_signing_enabled"`  // Activer la signature GPG
	GPGPrivateKeyPath string `json:"gpg_private_key_path"` // Chemin de la clé privée
	GPGPublicKeyPath  string `json:"gpg_public_key_path"`  // Chemin de la clé publique
	GPGKeyName        string `json:"gpg_key_name"`         // Nom pour la clé
	GPGKeyEmail       string `json:"gpg_key_email"`        // Email pour la clé
	GPGKeyComment     string `json:"gpg_key_comment"`      // Commentaire pour la clé

	// Paramètres multi-miroirs
	MultiMirrorEnabled        bool           `json:"multi_mirror_enabled"`         // Activer multi-miroirs
	DebianMirrors             []MirrorConfig `json:"debian_mirrors"`               // Liste des miroirs
	MirrorHealthCheckInterval int            `json:"mirror_health_check_interval"` // Intervalle health check (secondes)

	// Paramètres réseau
	NetworkInterface string `json:"network_interface"` // Interface réseau de sortie (ex: "eth0", "ens33", vide = auto)
	ProxyEnabled     bool   `json:"proxy_enabled"`     // Activer le proxy
	ProxyURL         string `json:"proxy_url"`         // URL du proxy (ex: "http://proxy.example.com:8080")
	ProxyUsername    string `json:"proxy_username"`    // Nom d'utilisateur pour le proxy (optionnel)
	ProxyPassword    string `json:"proxy_password"`    // Mot de passe pour le proxy (optionnel)

	// Paramètres Artica Repository
	SyncArticaRepository bool `json:"sync_artica_repository"` // Activer la synchronisation des dépôts Artica
	ArticaRepositorySSL  bool `json:"artica_repository_ssl"`  // Utiliser HTTPS pour les dépôts Artica

	// Paramètres de validation d'intégrité
	IntegrityCheckEnabled bool `json:"integrity_check_enabled"` // Activer la validation des checksums
	IntegrityAutoRetry    bool `json:"integrity_auto_retry"`    // Re-télécharger automatiquement les fichiers corrompus
	IntegrityMaxRetries   int  `json:"integrity_max_retries"`   // Nombre maximum de tentatives (défaut: 3)

	// Paramètres d'optimisation du stockage
	StorageDeduplicationEnabled bool   `json:"storage_deduplication_enabled"` // Activer la déduplication (hard links)
	StorageCleanupEnabled       bool   `json:"storage_cleanup_enabled"`       // Activer le nettoyage automatique
	StorageKeepOldPackages      int    `json:"storage_keep_old_packages"`     // Nombre de versions anciennes à garder (0 = garder toutes)
	StorageTieringEnabled       bool   `json:"storage_tiering_enabled"`       // Activer le tiering SSD/HDD
	StorageSSDPath              string `json:"storage_ssd_path"`              // Chemin vers le stockage SSD (pour fichiers récents)
	StorageHDDPath              string `json:"storage_hdd_path"`              // Chemin vers le stockage HDD (pour fichiers anciens)
	StorageTieringAgeDays       int    `json:"storage_tiering_age_days"`      // Age en jours avant migration vers HDD

	// Paramètres du scanner CVE
	CVEScannerEnabled   bool   `json:"cve_scanner_enabled"`    // Activer le scanner CVE
	CVEScanAfterSync    bool   `json:"cve_scan_after_sync"`    // Scanner automatiquement après la synchronisation
	CVECacheExpiryHours int    `json:"cve_cache_expiry_hours"` // Durée de validité du cache CVE en heures
	CVENVDEnabled       bool   `json:"cve_nvd_enabled"`        // Activer l'intégration NVD pour les scores CVSS
	CVENVDAPIKey        string `json:"cve_nvd_api_key"`        // Clé API NVD (optionnel, améliore le rate limit)
	CVEOSVEnabled       bool   `json:"cve_osv_enabled"`        // Activer l'intégration OSV.dev

	// Paramètres de la console web
	WebConsoleEnabled          bool   `json:"web_console_enabled"`             // Activer la console web
	WebConsolePort             int    `json:"web_console_port"`                // Port de la console web
	WebConsoleListenAddr       string `json:"web_console_listen_addr"`         // Adresse d'écoute (127.0.0.1 ou 0.0.0.0)
	WebConsoleHTTPSEnabled     bool   `json:"web_console_https_enabled"`       // Activer HTTPS pour la console
	WebConsoleTLSUseServerCert bool   `json:"web_console_tls_use_server_cert"` // Utiliser le même certificat que le serveur HTTP
	WebConsoleTLSCertFile      string `json:"web_console_tls_cert_file"`       // Certificat TLS pour la console (si use_server_cert=false)
	WebConsoleTLSKeyFile       string `json:"web_console_tls_key_file"`        // Clé TLS pour la console (si use_server_cert=false)
	WebConsoleSessionSecret    string `json:"web_console_session_secret"`      // Secret pour les sessions (généré si vide)
	WebConsoleSessionTimeout   int    `json:"web_console_session_timeout"`     // Timeout des sessions en minutes

	mu sync.RWMutex
}

// MirrorConfig représente la configuration d'un miroir
type MirrorConfig struct {
	URL      string `json:"url"`      // URL du miroir
	Priority int    `json:"priority"` // Priorité (plus bas = plus prioritaire)
	Enabled  bool   `json:"enabled"`  // Activé ou non
}

// DefaultConfig retourne une configuration par défaut
func DefaultConfig() *Config {
	return &Config{
		SyncInterval:                60, // 1 heure
		RepositoryPath:              "/var/lib/ActiveDebianSync/mirror",
		DebianMirror:                "http://deb.debian.org/debian",
		DebianReleases:              []string{"bookworm", "trixie"},
		DebianArchs:                 []string{"amd64"},
		DebianComponents:            []string{"main", "contrib", "non-free", "non-free-firmware"},
		SyncPackages:                true,                // Télécharger les packages par défaut
		SyncContents:                true,                // Télécharger les fichiers Contents par défaut
		PackageSearchEnabled:        true,                // Activer la recherche par défaut
		SyncDebianInstaller:         false,               // Désactivé par défaut (volumineux)
		SyncInstallerUdebs:          true,                // Udebs activés si debian-installer est activé
		SyncInstallerImages:         true,                // Images activées si debian-installer est activé
		InstallerImageTypes:         []string{"netboot"}, // Seulement netboot par défaut (le plus léger)
		MaxConcurrentDownloads:      4,                   // 4 téléchargements parallèles
		DownloadBandwidthLimit:      0,                   // Illimité par défaut
		BlockClientsDuringSync:      true,                // Bloquer par défaut pour éviter corruptions
		SyncAllowedHoursEnabled:     false,               // Pas de restriction horaire par défaut
		SyncAllowedHoursStart:       "02:00",             // 2h du matin
		SyncAllowedHoursEnd:         "06:00",             // 6h du matin
		HTTPEnabled:                 true,
		HTTPPort:                    8080,
		HTTPSEnabled:                false,
		HTTPSPort:                   8443,
		TLSCertFile:                 "/etc/ActiveDebianSync/server.crt",
		TLSKeyFile:                  "/etc/ActiveDebianSync/server.key",
		APIEnabled:                  true,
		APIPort:                     9090,
		APIListenAddr:               "127.0.0.1",
		APIAllowedIPs:               []string{},
		MaxDiskUsagePercent:         90,
		LogPath:                     "/var/log/ActiveDebianSync/sync.log",
		AccessLogPath:               "/var/log/ActiveDebianSync/access.log",
		PIDFile:                     "/var/run/activedebiansync.pid",
		RunAsUser:                   "", // Vide = ne pas changer d'utilisateur
		RunAsGroup:                  "", // Vide = ne pas changer de groupe
		GPGSigningEnabled:           false,
		GPGPrivateKeyPath:           "/etc/ActiveDebianSync/gpg/private.key",
		GPGPublicKeyPath:            "/etc/ActiveDebianSync/gpg/public.key",
		GPGKeyName:                  "ActiveDebianSync Repository",
		GPGKeyEmail:                 "repo@activedebiansync.local",
		GPGKeyComment:               "Automatic repository signing key",
		MultiMirrorEnabled:          false, // Désactivé par défaut
		DebianMirrors:               []MirrorConfig{},
		MirrorHealthCheckInterval:   300, // 5 minutes
		NetworkInterface:            "",  // Auto-détection par défaut
		ProxyEnabled:                false,
		ProxyURL:                    "",
		ProxyUsername:               "",
		ProxyPassword:               "",
		SyncArticaRepository:        false, // Désactivé par défaut
		ArticaRepositorySSL:         false, // HTTP par défaut
		IntegrityCheckEnabled:       true,  // Activé par défaut pour la sécurité
		IntegrityAutoRetry:          true,
		IntegrityMaxRetries:         3,
		StorageDeduplicationEnabled: true,  // Activé par défaut pour économiser l'espace
		StorageCleanupEnabled:       false, // Désactivé par défaut (dangereux)
		StorageKeepOldPackages:      2,     // Garder 2 versions anciennes
		StorageTieringEnabled:       false, // Désactivé par défaut
		StorageSSDPath:              "",
		StorageHDDPath:              "",
		StorageTieringAgeDays:       30, // 30 jours
		// Scanner CVE
		CVEScannerEnabled:   true, // Activé par défaut
		CVEScanAfterSync:    true, // Scanner après sync par défaut
		CVECacheExpiryHours: 6,    // 6 heures de cache
		CVENVDEnabled:       true, // NVD activé par défaut pour les scores CVSS
		CVENVDAPIKey:        "",   // Clé API NVD optionnelle
		CVEOSVEnabled:       true, // OSV.dev activé par défaut

		// Console web
		WebConsoleEnabled:          false, // Désactivé par défaut
		WebConsolePort:             8090,
		WebConsoleListenAddr:       "127.0.0.1",
		WebConsoleHTTPSEnabled:     false,
		WebConsoleTLSUseServerCert: true, // Par défaut, utiliser le certificat du serveur HTTP
		WebConsoleTLSCertFile:      "/etc/ActiveDebianSync/console.crt",
		WebConsoleTLSKeyFile:       "/etc/ActiveDebianSync/console.key",
		WebConsoleSessionSecret:    "", // Généré automatiquement si vide
		WebConsoleSessionTimeout:   60, // 60 minutes
	}
}

// LoadConfig charge la configuration depuis un fichier JSON
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Créer le répertoire si nécessaire
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Si le fichier n'existe pas, créer avec config par défaut
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
		return cfg, nil
	}

	// Charger le fichier existant
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	cfg.ConfigPath = path
	return cfg, nil
}

// Save sauvegarde la configuration dans un fichier JSON
func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Get retourne une copie en lecture seule de la config
func (c *Config) Get() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c
}

// Update met à jour la configuration
func (c *Config) Update(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}

// GetReleaseConfig returns the configuration for a specific release
// If no specific config exists, returns a default config based on the release name
func (c *Config) GetReleaseConfig(releaseName string) ReleaseConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if there's a specific config for this release
	for _, rc := range c.ReleaseConfigs {
		if rc.Name == releaseName {
			return rc
		}
	}

	// Return default config for this release
	return c.defaultReleaseConfig(releaseName)
}

// defaultReleaseConfig returns a default ReleaseConfig for a release
func (c *Config) defaultReleaseConfig(releaseName string) ReleaseConfig {
	// Known archived releases
	archivedReleases := map[string]bool{
		"buzz": true, "rex": true, "bo": true, "hamm": true, "slink": true,
		"potato": true, "woody": true, "sarge": true, "etch": true,
		"lenny": true, "squeeze": true, "wheezy": true, "jessie": true,
		"stretch": true, "buster": true,
	}

	isArchived := archivedReleases[releaseName]

	rc := ReleaseConfig{
		Name:          releaseName,
		Mirror:        c.DebianMirror,
		IsArchived:    isArchived,
		SyncUpdates:   true,
		SyncBackports: false,
		SyncSecurity:  true,
		Components:    c.DebianComponents,
	}

	if isArchived {
		rc.Mirror = "http://archive.debian.org/debian"
		rc.SecurityMirror = "http://archive.debian.org/debian-security"
		// Old security path format for releases before bullseye
		rc.SecuritySuite = releaseName + "/updates"
		// Old releases don't have non-free-firmware
		rc.Components = filterComponents(c.DebianComponents, "non-free-firmware")
	} else {
		// Current releases use the standard format
		rc.SecurityMirror = "http://security.debian.org/debian-security"
		rc.SecuritySuite = releaseName + "-security"
	}

	return rc
}

// GetAllReleaseConfigs returns release configs for all configured releases
func (c *Config) GetAllReleaseConfigs() []ReleaseConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	configs := make([]ReleaseConfig, 0, len(c.DebianReleases))
	for _, releaseName := range c.DebianReleases {
		configs = append(configs, c.GetReleaseConfig(releaseName))
	}
	return configs
}

// filterComponents removes a component from the list
func filterComponents(components []string, toRemove string) []string {
	result := make([]string, 0, len(components))
	for _, c := range components {
		if c != toRemove {
			result = append(result, c)
		}
	}
	return result
}
