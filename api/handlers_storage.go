package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// handleStorageDeduplicate lance la déduplication des fichiers
func (api *RestAPI) handleStorageDeduplicate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	api.logger.LogInfo("Starting deduplication via API request")

	optimizer := api.syncer.GetOptimizer()
	if optimizer == nil {
		http.Error(w, "Optimizer not available", http.StatusInternalServerError)
		return
	}

	// La déduplication sera effectuée de manière asynchrone
	go func() {
		api.logger.LogInfo("Deduplication task started")
		report, err := optimizer.DeduplicateFiles()
		if err != nil {
			api.logger.LogError("Deduplication failed: %v", err)
			return
		}
		api.logger.LogInfo("Deduplication completed: %d groups, %d hard links created, %.2f MB saved",
			report.DuplicateGroups, report.HardLinksCreated, float64(report.SpaceSavedBytes)/1024/1024)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "started",
		"message": "Deduplication task started in background",
	})
}

// handleStorageCleanup lance le nettoyage des anciens packages
func (api *RestAPI) handleStorageCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.StorageCleanupEnabled {
		http.Error(w, "Storage cleanup is disabled in configuration", http.StatusForbidden)
		return
	}

	api.logger.LogInfo("Starting cleanup via API request")

	optimizer := api.syncer.GetOptimizer()
	if optimizer == nil {
		http.Error(w, "Optimizer not available", http.StatusInternalServerError)
		return
	}

	// Le nettoyage sera effectué de manière asynchrone
	go func() {
		api.logger.LogInfo("Cleanup task started")
		report, err := optimizer.CleanupOldPackages()
		if err != nil {
			api.logger.LogError("Cleanup failed: %v", err)
			return
		}
		api.logger.LogInfo("Cleanup completed: %d files removed, %.2f MB freed",
			report.FilesRemoved, float64(report.SpaceFreedBytes)/1024/1024)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "started",
		"message": "Cleanup task started in background",
	})
}

// handleStorageTier lance le tiering SSD/HDD
func (api *RestAPI) handleStorageTier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := api.config.Get()
	if !cfg.StorageTieringEnabled {
		http.Error(w, "Storage tiering is disabled in configuration", http.StatusForbidden)
		return
	}

	api.logger.LogInfo("Starting tiering via API request")

	optimizer := api.syncer.GetOptimizer()
	if optimizer == nil {
		http.Error(w, "Optimizer not available", http.StatusInternalServerError)
		return
	}

	// Le tiering sera effectué de manière asynchrone
	go func() {
		api.logger.LogInfo("Tiering task started")
		err := optimizer.TierFiles()
		if err != nil {
			api.logger.LogError("Tiering failed: %v", err)
			return
		}
		api.logger.LogInfo("Tiering completed successfully")
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "started",
		"message": "Tiering task started in background",
	})
}

// handleStorageStats retourne les statistiques de stockage
func (api *RestAPI) handleStorageStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	optimizer := api.syncer.GetOptimizer()
	if optimizer == nil {
		http.Error(w, "Optimizer not available", http.StatusInternalServerError)
		return
	}

	stats, err := optimizer.GetStorageStats()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get storage stats: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
