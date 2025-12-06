package scheduler

import (
	"activedebiansync/config"
	"activedebiansync/storage"
	"activedebiansync/utils"
	"context"
	"time"
)

// Scheduler gère les tâches planifiées d'optimisation
type Scheduler struct {
	config    *config.Config
	logger    *utils.Logger
	optimizer *storage.Optimizer
	stopChan  chan struct{}
}

// NewScheduler crée une nouvelle instance de Scheduler
func NewScheduler(cfg *config.Config, logger *utils.Logger, optimizer *storage.Optimizer) *Scheduler {
	return &Scheduler{
		config:    cfg,
		logger:    logger,
		optimizer: optimizer,
		stopChan:  make(chan struct{}),
	}
}

// Start démarre le scheduler
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.LogInfo("Starting optimization scheduler")

	// Démarrer la déduplication quotidienne
	go s.dailyDeduplication(ctx)

	// Démarrer le nettoyage hebdomadaire
	go s.weeklyCleanup(ctx)

	// Démarrer le tiering nocturne
	go s.nocturnalTiering(ctx)

	// Attendre l'arrêt
	<-s.stopChan
	s.logger.LogInfo("Optimization scheduler stopped")
}

// Stop arrête le scheduler
func (s *Scheduler) Stop() {
	close(s.stopChan)
}

// dailyDeduplication exécute la déduplication tous les jours à 3h du matin
func (s *Scheduler) dailyDeduplication(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Vérifier toutes les heures
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case now := <-ticker.C:
			// Exécuter à 3h du matin
			if now.Hour() == 3 && now.Minute() < 5 {
				cfg := s.config.Get()
				if cfg.StorageDeduplicationEnabled {
					s.logger.LogInfo("Starting scheduled deduplication")
					report, err := s.optimizer.DeduplicateFiles()
					if err != nil {
						s.logger.LogError("Scheduled deduplication failed: %v", err)
					} else {
						s.logger.LogInfo("Scheduled deduplication completed: %d groups, %d hard links created, %.2f MB saved",
							report.DuplicateGroups, report.HardLinksCreated, float64(report.SpaceSavedBytes)/1024/1024)
					}
					// Attendre 1 heure pour ne pas re-exécuter
					time.Sleep(1 * time.Hour)
				}
			}
		}
	}
}

// weeklyCleanup exécute le nettoyage tous les dimanches à 2h du matin
func (s *Scheduler) weeklyCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Vérifier toutes les heures
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case now := <-ticker.C:
			// Exécuter le dimanche à 2h du matin
			if now.Weekday() == time.Sunday && now.Hour() == 2 && now.Minute() < 5 {
				cfg := s.config.Get()
				if cfg.StorageCleanupEnabled {
					s.logger.LogInfo("Starting scheduled cleanup")
					report, err := s.optimizer.CleanupOldPackages()
					if err != nil {
						s.logger.LogError("Scheduled cleanup failed: %v", err)
					} else {
						s.logger.LogInfo("Scheduled cleanup completed: %d files removed, %.2f MB freed",
							report.FilesRemoved, float64(report.SpaceFreedBytes)/1024/1024)
					}
					// Attendre 1 heure pour ne pas re-exécuter
					time.Sleep(1 * time.Hour)
				}
			}
		}
	}
}

// nocturnalTiering exécute le tiering tous les jours à 1h du matin
func (s *Scheduler) nocturnalTiering(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Vérifier toutes les heures
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case now := <-ticker.C:
			// Exécuter à 1h du matin
			if now.Hour() == 1 && now.Minute() < 5 {
				cfg := s.config.Get()
				if cfg.StorageTieringEnabled {
					s.logger.LogInfo("Starting scheduled tiering")
					err := s.optimizer.TierFiles()
					if err != nil {
						s.logger.LogError("Scheduled tiering failed: %v", err)
					} else {
						s.logger.LogInfo("Scheduled tiering completed successfully")
					}
					// Attendre 1 heure pour ne pas re-exécuter
					time.Sleep(1 * time.Hour)
				}
			}
		}
	}
}

// RunDeduplicationNow exécute immédiatement la déduplication
func (s *Scheduler) RunDeduplicationNow() error {
	cfg := s.config.Get()
	if !cfg.StorageDeduplicationEnabled {
		s.logger.LogInfo("Deduplication is disabled")
		return nil
	}

	s.logger.LogInfo("Running deduplication on demand")
	report, err := s.optimizer.DeduplicateFiles()
	if err != nil {
		return err
	}

	s.logger.LogInfo("Deduplication completed: %d groups, %d hard links created, %.2f MB saved",
		report.DuplicateGroups, report.HardLinksCreated, float64(report.SpaceSavedBytes)/1024/1024)
	return nil
}

// RunCleanupNow exécute immédiatement le nettoyage
func (s *Scheduler) RunCleanupNow() error {
	cfg := s.config.Get()
	if !cfg.StorageCleanupEnabled {
		s.logger.LogInfo("Cleanup is disabled")
		return nil
	}

	s.logger.LogInfo("Running cleanup on demand")
	report, err := s.optimizer.CleanupOldPackages()
	if err != nil {
		return err
	}

	s.logger.LogInfo("Cleanup completed: %d files removed, %.2f MB freed",
		report.FilesRemoved, float64(report.SpaceFreedBytes)/1024/1024)
	return nil
}

// RunTieringNow exécute immédiatement le tiering
func (s *Scheduler) RunTieringNow() error {
	cfg := s.config.Get()
	if !cfg.StorageTieringEnabled {
		s.logger.LogInfo("Tiering is disabled")
		return nil
	}

	s.logger.LogInfo("Running tiering on demand")
	err := s.optimizer.TierFiles()
	if err != nil {
		return err
	}

	s.logger.LogInfo("Tiering completed successfully")
	return nil
}
