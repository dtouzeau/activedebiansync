package mirrors

import (
	"activedebiansync/config"
	"activedebiansync/utils"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MirrorStatus représente l'état d'un miroir
type MirrorStatus int

const (
	StatusUnknown MirrorStatus = iota
	StatusHealthy
	StatusUnhealthy
)

// Mirror représente un miroir Debian
type Mirror struct {
	URL             string       `json:"url"`
	Priority        int          `json:"priority"` // Plus bas = plus prioritaire
	Enabled         bool         `json:"enabled"`
	Status          MirrorStatus `json:"status"`
	LastCheck       time.Time    `json:"last_check"`
	LastSuccess     time.Time    `json:"last_success"`
	LastError       string       `json:"last_error,omitempty"`
	ConsecutiveFails int         `json:"consecutive_fails"`
	mu              sync.RWMutex
}

// MirrorManager gère les miroirs multiples avec failover
type MirrorManager struct {
	config          *config.Config
	logger          *utils.Logger
	mirrors         []*Mirror
	currentMirror   *Mirror
	httpClient      *http.Client
	healthCheckStop chan struct{}
	mu              sync.RWMutex
}

// NewMirrorManager crée une nouvelle instance de MirrorManager
func NewMirrorManager(cfg *config.Config, logger *utils.Logger) *MirrorManager {
	cfgData := cfg.Get()

	// Créer le HTTP client avec support de l'interface réseau et du proxy
	httpClientConfig := utils.HTTPClientConfig{
		NetworkInterface: cfgData.NetworkInterface,
		ProxyEnabled:     cfgData.ProxyEnabled,
		ProxyURL:         cfgData.ProxyURL,
		ProxyUsername:    cfgData.ProxyUsername,
		ProxyPassword:    cfgData.ProxyPassword,
		Timeout:          10 * time.Second, // Timeout court pour les health checks
	}

	httpClient, err := utils.NewHTTPClient(httpClientConfig)
	if err != nil {
		logger.LogError("Failed to create HTTP client for mirror manager: %v, using default", err)
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	mm := &MirrorManager{
		config:          cfg,
		logger:          logger,
		mirrors:         make([]*Mirror, 0),
		httpClient:      httpClient,
		healthCheckStop: make(chan struct{}),
	}

	// Initialiser les miroirs depuis la config
	mm.initMirrors()

	return mm
}

// initMirrors initialise la liste des miroirs depuis la configuration
func (mm *MirrorManager) initMirrors() {
	cfg := mm.config.Get()

	// Si multi-miroirs est activé, utiliser la liste
	if cfg.MultiMirrorEnabled && len(cfg.DebianMirrors) > 0 {
		for _, mirrorCfg := range cfg.DebianMirrors {
			mirror := &Mirror{
				URL:      mirrorCfg.URL,
				Priority: mirrorCfg.Priority,
				Enabled:  mirrorCfg.Enabled,
				Status:   StatusUnknown,
			}
			mm.mirrors = append(mm.mirrors, mirror)
		}

		// Trier par priorité (plus bas = plus prioritaire)
		mm.sortByPriority()

		mm.logger.LogInfo("Initialized %d mirrors", len(mm.mirrors))
	} else {
		// Mode legacy : un seul miroir
		mirror := &Mirror{
			URL:      cfg.DebianMirror,
			Priority: 1,
			Enabled:  true,
			Status:   StatusUnknown,
		}
		mm.mirrors = append(mm.mirrors, mirror)
		mm.logger.LogInfo("Using single mirror mode: %s", cfg.DebianMirror)
	}

	// Sélectionner le miroir initial
	mm.selectBestMirror()
}

// sortByPriority trie les miroirs par priorité
func (mm *MirrorManager) sortByPriority() {
	// Tri par insertion simple
	for i := 1; i < len(mm.mirrors); i++ {
		key := mm.mirrors[i]
		j := i - 1
		for j >= 0 && mm.mirrors[j].Priority > key.Priority {
			mm.mirrors[j+1] = mm.mirrors[j]
			j--
		}
		mm.mirrors[j+1] = key
	}
}

// selectBestMirror sélectionne le meilleur miroir disponible
func (mm *MirrorManager) selectBestMirror() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Chercher le premier miroir enabled et healthy (ou unknown)
	for _, mirror := range mm.mirrors {
		if mirror.Enabled && (mirror.Status == StatusHealthy || mirror.Status == StatusUnknown) {
			mm.currentMirror = mirror
			mm.logger.LogInfo("Selected mirror: %s (priority %d)", mirror.URL, mirror.Priority)
			return
		}
	}

	// Si aucun miroir healthy, prendre le premier enabled
	for _, mirror := range mm.mirrors {
		if mirror.Enabled {
			mm.currentMirror = mirror
			mm.logger.LogInfo("Selected mirror (fallback): %s (priority %d)", mirror.URL, mirror.Priority)
			return
		}
	}

	// Dernier recours : prendre le premier
	if len(mm.mirrors) > 0 {
		mm.currentMirror = mm.mirrors[0]
		mm.logger.LogInfo("Selected mirror (last resort): %s", mm.currentMirror.URL)
	}
}

// GetCurrentMirror retourne le miroir actuellement sélectionné
func (mm *MirrorManager) GetCurrentMirror() string {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if mm.currentMirror != nil {
		return mm.currentMirror.URL
	}

	return ""
}

// MarkMirrorFailed marque le miroir actuel comme ayant échoué et bascule
func (mm *MirrorManager) MarkMirrorFailed(mirrorURL string, err error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Trouver le miroir
	for _, mirror := range mm.mirrors {
		if mirror.URL == mirrorURL {
			mirror.mu.Lock()
			mirror.ConsecutiveFails++
			mirror.LastError = err.Error()
			mirror.LastCheck = time.Now()

			// Marquer comme unhealthy après 3 échecs consécutifs
			if mirror.ConsecutiveFails >= 3 {
				mirror.Status = StatusUnhealthy
				mm.logger.LogError("Mirror marked as unhealthy: %s (consecutive fails: %d)", mirrorURL, mirror.ConsecutiveFails)
			}
			mirror.mu.Unlock()

			// Si c'est le miroir courant, basculer
			if mm.currentMirror != nil && mm.currentMirror.URL == mirrorURL {
				mm.logger.LogInfo("Current mirror failed, attempting failover...")
				mm.mu.Unlock() // Unlock avant d'appeler selectBestMirror qui va re-lock
				mm.selectBestMirror()
				mm.mu.Lock() // Re-lock pour le defer
			}

			break
		}
	}
}

// MarkMirrorSuccess marque le miroir comme ayant réussi
func (mm *MirrorManager) MarkMirrorSuccess(mirrorURL string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	for _, mirror := range mm.mirrors {
		if mirror.URL == mirrorURL {
			mirror.mu.Lock()
			mirror.Status = StatusHealthy
			mirror.ConsecutiveFails = 0
			mirror.LastSuccess = time.Now()
			mirror.LastCheck = time.Now()
			mirror.LastError = ""
			mirror.mu.Unlock()
			break
		}
	}
}

// StartHealthCheck démarre le health check périodique des miroirs
func (mm *MirrorManager) StartHealthCheck() {
	cfg := mm.config.Get()

	if !cfg.MultiMirrorEnabled {
		mm.logger.LogInfo("Multi-mirror disabled, skipping health checks")
		return
	}

	interval := time.Duration(cfg.MirrorHealthCheckInterval) * time.Second
	mm.logger.LogInfo("Starting mirror health checks (interval: %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				mm.checkAllMirrors()
			case <-mm.healthCheckStop:
				return
			}
		}
	}()
}

// StopHealthCheck arrête le health check
func (mm *MirrorManager) StopHealthCheck() {
	close(mm.healthCheckStop)
}

// checkAllMirrors vérifie la santé de tous les miroirs
func (mm *MirrorManager) checkAllMirrors() {
	mm.logger.LogInfo("Checking health of all mirrors...")

	for _, mirror := range mm.mirrors {
		if !mirror.Enabled {
			continue
		}

		go mm.checkMirrorHealth(mirror)
	}
}

// checkMirrorHealth vérifie la santé d'un miroir spécifique
func (mm *MirrorManager) checkMirrorHealth(mirror *Mirror) {
	// Construire l'URL de test (fichier Release de bookworm)
	testURL := fmt.Sprintf("%s/dists/bookworm/Release", mirror.URL)

	resp, err := mm.httpClient.Head(testURL)
	if err != nil {
		mirror.mu.Lock()
		mirror.Status = StatusUnhealthy
		mirror.LastError = err.Error()
		mirror.LastCheck = time.Now()
		mirror.ConsecutiveFails++
		mirror.mu.Unlock()

		mm.logger.LogError("Mirror health check failed: %s - %v", mirror.URL, err)
		return
	}
	defer resp.Body.Close()

	mirror.mu.Lock()
	if resp.StatusCode == http.StatusOK {
		wasUnhealthy := mirror.Status == StatusUnhealthy
		mirror.Status = StatusHealthy
		mirror.LastSuccess = time.Now()
		mirror.ConsecutiveFails = 0
		mirror.LastError = ""

		if wasUnhealthy {
			mm.logger.LogInfo("Mirror recovered: %s", mirror.URL)

			// Si c'était un miroir de plus haute priorité, le réactiver
			mm.mu.RLock()
			currentPriority := mm.currentMirror.Priority
			mm.mu.RUnlock()

			if mirror.Priority < currentPriority {
				mm.logger.LogInfo("Higher priority mirror available, switching back...")
				mm.selectBestMirror()
			}
		}
	} else {
		mirror.Status = StatusUnhealthy
		mirror.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		mirror.ConsecutiveFails++
	}
	mirror.LastCheck = time.Now()
	mirror.mu.Unlock()
}

// GetMirrorStats retourne les statistiques de tous les miroirs
func (mm *MirrorManager) GetMirrorStats() []MirrorStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	stats := make([]MirrorStats, len(mm.mirrors))

	for i, mirror := range mm.mirrors {
		mirror.mu.RLock()
		stats[i] = MirrorStats{
			URL:              mirror.URL,
			Priority:         mirror.Priority,
			Enabled:          mirror.Enabled,
			Status:           mirror.Status.String(),
			IsCurrent:        mm.currentMirror != nil && mm.currentMirror.URL == mirror.URL,
			LastCheck:        mirror.LastCheck,
			LastSuccess:      mirror.LastSuccess,
			LastError:        mirror.LastError,
			ConsecutiveFails: mirror.ConsecutiveFails,
		}
		mirror.mu.RUnlock()
	}

	return stats
}

// MirrorStats représente les statistiques d'un miroir pour l'API
type MirrorStats struct {
	URL              string    `json:"url"`
	Priority         int       `json:"priority"`
	Enabled          bool      `json:"enabled"`
	Status           string    `json:"status"`
	IsCurrent        bool      `json:"is_current"`
	LastCheck        time.Time `json:"last_check"`
	LastSuccess      time.Time `json:"last_success"`
	LastError        string    `json:"last_error,omitempty"`
	ConsecutiveFails int       `json:"consecutive_fails"`
}

// String retourne la représentation en chaîne du status
func (s MirrorStatus) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}
