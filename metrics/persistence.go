package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistedMetrics contient toutes les métriques à persister entre les redémarrages
type PersistedMetrics struct {
	// Sync stats
	SyncTotalFiles       int64     `json:"sync_total_files"`
	SyncTotalBytes       int64     `json:"sync_total_bytes"`
	SyncFailedFiles      int64     `json:"sync_failed_files"`
	SyncLastStart        time.Time `json:"sync_last_start"`
	SyncLastEnd          time.Time `json:"sync_last_end"`
	SyncLastDuration     string    `json:"sync_last_duration"`
	SyncLastError        string    `json:"sync_last_error,omitempty"`

	// Server stats
	ServerTotalRequests  int64 `json:"server_total_requests"`
	ServerTotalBytesSent int64 `json:"server_total_bytes_sent"`

	// Client tracker
	Clients []PersistedClient `json:"clients,omitempty"`

	// Metadata
	SavedAt time.Time `json:"saved_at"`
	Version string    `json:"version"`
}

// PersistedClient contient les informations d'un client à persister
type PersistedClient struct {
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	RequestCount  int64     `json:"request_count"`
	BytesReceived int64     `json:"bytes_received"`
}

// MetricsPersistence gère la sauvegarde et le chargement des métriques
type MetricsPersistence struct {
	filePath string
	mu       sync.RWMutex
}

// NewMetricsPersistence crée une nouvelle instance de MetricsPersistence
// configPath est le chemin vers le fichier de configuration, les métriques seront
// sauvegardées dans le même répertoire sous le nom "metrics.json"
func NewMetricsPersistence(configPath string) *MetricsPersistence {
	dir := filepath.Dir(configPath)
	metricsFile := filepath.Join(dir, "metrics.json")

	return &MetricsPersistence{
		filePath: metricsFile,
	}
}

// GetFilePath retourne le chemin du fichier de métriques
func (mp *MetricsPersistence) GetFilePath() string {
	return mp.filePath
}

// Save sauvegarde les métriques dans le fichier
func (mp *MetricsPersistence) Save(metrics *PersistedMetrics) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Mettre à jour les métadonnées
	metrics.SavedAt = time.Now()
	metrics.Version = "1.0"

	// Créer le répertoire si nécessaire
	dir := filepath.Dir(mp.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory: %w", err)
	}

	// Sérialiser en JSON avec indentation
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Écrire dans un fichier temporaire puis renommer (atomique)
	tmpFile := mp.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write metrics file: %w", err)
	}

	if err := os.Rename(tmpFile, mp.filePath); err != nil {
		os.Remove(tmpFile) // Nettoyer en cas d'erreur
		return fmt.Errorf("failed to rename metrics file: %w", err)
	}

	return nil
}

// Load charge les métriques depuis le fichier
func (mp *MetricsPersistence) Load() (*PersistedMetrics, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	// Vérifier si le fichier existe
	if _, err := os.Stat(mp.filePath); os.IsNotExist(err) {
		return nil, nil // Pas de fichier, pas d'erreur
	}

	// Lire le fichier
	data, err := os.ReadFile(mp.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metrics file: %w", err)
	}

	// Désérialiser
	var metrics PersistedMetrics
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metrics: %w", err)
	}

	return &metrics, nil
}

// Exists vérifie si le fichier de métriques existe
func (mp *MetricsPersistence) Exists() bool {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	_, err := os.Stat(mp.filePath)
	return err == nil
}
