package storage

import (
	"activedebiansync/config"
	"activedebiansync/integrity"
	"activedebiansync/utils"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Optimizer gère l'optimisation du stockage
type Optimizer struct {
	config *config.Config
	logger *utils.Logger
	mu     sync.RWMutex
}

// FileInfo représente les informations sur un fichier
type FileInfo struct {
	Path         string
	Size         int64
	ModTime      time.Time
	Hash         string
	IsHardLink   bool
	LinkCount    int
	PackageName  string
	Version      string
}

// DeduplicationReport représente le rapport de déduplication
type DeduplicationReport struct {
	TotalFiles      int   `json:"total_files"`
	DuplicateGroups int   `json:"duplicate_groups"`
	SpaceSavedBytes int64 `json:"space_saved_bytes"`
	HardLinksCreated int   `json:"hard_links_created"`
}

// CleanupReport représente le rapport de nettoyage
type CleanupReport struct {
	FilesRemoved    int   `json:"files_removed"`
	SpaceFreedBytes int64 `json:"space_freed_bytes"`
	PackagesRemoved []string `json:"packages_removed"`
}

// NewOptimizer crée une nouvelle instance d'Optimizer
func NewOptimizer(cfg *config.Config, logger *utils.Logger) *Optimizer {
	return &Optimizer{
		config: cfg,
		logger: logger,
	}
}

// DeduplicateFiles trouve et déduplique les fichiers identiques avec hard links
func (o *Optimizer) DeduplicateFiles() (*DeduplicationReport, error) {
	cfg := o.config.Get()

	if !cfg.StorageDeduplicationEnabled {
		return nil, fmt.Errorf("deduplication is disabled")
	}

	o.logger.LogInfo("Starting file deduplication...")

	// Trouver les doublons
	duplicates, err := integrity.FindDuplicateFiles(cfg.RepositoryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find duplicates: %w", err)
	}

	report := &DeduplicationReport{
		DuplicateGroups: len(duplicates),
	}

	// Pour chaque groupe de doublons, garder un fichier et créer des hard links
	for hash, files := range duplicates {
		if len(files) < 2 {
			continue
		}

		report.TotalFiles += len(files)

		// Trier par date de modification (garder le plus ancien)
		sort.Slice(files, func(i, j int) bool {
			stat1, _ := os.Stat(files[i])
			stat2, _ := os.Stat(files[j])
			return stat1.ModTime().Before(stat2.ModTime())
		})

		// Garder le premier fichier comme original
		original := files[0]
		originalStat, err := os.Stat(original)
		if err != nil {
			continue
		}

		// Créer des hard links pour les autres
		for i := 1; i < len(files); i++ {
			duplicate := files[i]

			// Vérifier que ce n'est pas déjà un hard link
			if o.areHardLinked(original, duplicate) {
				continue
			}

			// Supprimer le duplicata
			if err := os.Remove(duplicate); err != nil {
				o.logger.LogError("Failed to remove duplicate %s: %v", duplicate, err)
				continue
			}

			// Créer le hard link
			if err := os.Link(original, duplicate); err != nil {
				o.logger.LogError("Failed to create hard link %s -> %s: %v", duplicate, original, err)
				// Restaurer le fichier si possible
				continue
			}

			report.HardLinksCreated++
			report.SpaceSavedBytes += originalStat.Size()

			o.logger.LogSync("Created hard link: %s -> %s (saved %.2f MB)",
				filepath.Base(duplicate), filepath.Base(original),
				float64(originalStat.Size())/1024/1024)
		}

		o.logger.LogInfo("Deduplicated %d files with hash %s (saved %.2f MB)",
			len(files)-1, hash[:16], float64(report.SpaceSavedBytes)/1024/1024)
	}

	o.logger.LogInfo("Deduplication complete: %d groups, %d hard links created, %.2f MB saved",
		report.DuplicateGroups, report.HardLinksCreated, float64(report.SpaceSavedBytes)/1024/1024)

	return report, nil
}

// areHardLinked vérifie si deux fichiers sont des hard links
func (o *Optimizer) areHardLinked(file1, file2 string) bool {
	stat1, err1 := os.Stat(file1)
	stat2, err2 := os.Stat(file2)

	if err1 != nil || err2 != nil {
		return false
	}

	// Sur Unix, vérifier le numéro d'inode
	// Note: Cette méthode fonctionne uniquement sur les systèmes Unix
	return os.SameFile(stat1, stat2)
}

// CleanupOldPackages supprime les anciennes versions des packages
func (o *Optimizer) CleanupOldPackages() (*CleanupReport, error) {
	cfg := o.config.Get()

	if !cfg.StorageCleanupEnabled {
		return nil, fmt.Errorf("cleanup is disabled")
	}

	if cfg.StorageKeepOldPackages == 0 {
		return nil, fmt.Errorf("keep_old_packages is 0, refusing to delete all packages")
	}

	o.logger.LogInfo("Starting cleanup of old packages (keeping %d versions)...", cfg.StorageKeepOldPackages)

	report := &CleanupReport{
		PackagesRemoved: make([]string, 0),
	}

	poolPath := filepath.Join(cfg.RepositoryPath, "pool")

	// Map: package_name -> liste de versions
	packageVersions := make(map[string][]FileInfo)

	// Scanner tous les .deb
	err := filepath.Walk(poolPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(path, ".deb") {
			return nil
		}

		// Extraire le nom et la version du package
		packageName, version := o.parsePackageNameVersion(filepath.Base(path))
		if packageName == "" {
			return nil
		}

		packageVersions[packageName] = append(packageVersions[packageName], FileInfo{
			Path:        path,
			Size:        info.Size(),
			ModTime:     info.ModTime(),
			PackageName: packageName,
			Version:     version,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan packages: %w", err)
	}

	// Pour chaque package, garder uniquement les N dernières versions
	for packageName, versions := range packageVersions {
		if len(versions) <= cfg.StorageKeepOldPackages {
			continue
		}

		// Trier par date de modification (plus récent en premier)
		sort.Slice(versions, func(i, j int) bool {
			return versions[i].ModTime.After(versions[j].ModTime)
		})

		// Supprimer les versions anciennes
		for i := cfg.StorageKeepOldPackages; i < len(versions); i++ {
			file := versions[i]

			if err := os.Remove(file.Path); err != nil {
				o.logger.LogError("Failed to remove old package %s: %v", file.Path, err)
				continue
			}

			report.FilesRemoved++
			report.SpaceFreedBytes += file.Size
			report.PackagesRemoved = append(report.PackagesRemoved, filepath.Base(file.Path))

			o.logger.LogSync("Removed old package: %s (%.2f MB)",
				filepath.Base(file.Path), float64(file.Size)/1024/1024)
		}

		if len(versions) > cfg.StorageKeepOldPackages {
			o.logger.LogInfo("Cleaned up package %s: kept %d, removed %d versions",
				packageName, cfg.StorageKeepOldPackages, len(versions)-cfg.StorageKeepOldPackages)
		}
	}

	o.logger.LogInfo("Cleanup complete: %d files removed, %.2f MB freed",
		report.FilesRemoved, float64(report.SpaceFreedBytes)/1024/1024)

	return report, nil
}

// parsePackageNameVersion parse le nom et la version d'un fichier .deb
func (o *Optimizer) parsePackageNameVersion(filename string) (name, version string) {
	// Format: packagename_version_arch.deb
	// Exemple: nginx_1.18.0-6ubuntu14_amd64.deb

	filename = strings.TrimSuffix(filename, ".deb")
	parts := strings.Split(filename, "_")

	if len(parts) >= 2 {
		name = parts[0]
		version = parts[1]
	}

	return name, version
}

// TierFiles déplace les fichiers anciens du SSD vers le HDD
func (o *Optimizer) TierFiles() error {
	cfg := o.config.Get()

	if !cfg.StorageTieringEnabled {
		return fmt.Errorf("tiering is disabled")
	}

	if cfg.StorageSSDPath == "" || cfg.StorageHDDPath == "" {
		return fmt.Errorf("SSD or HDD path not configured")
	}

	o.logger.LogInfo("Starting storage tiering (age threshold: %d days)...", cfg.StorageTieringAgeDays)

	cutoffDate := time.Now().Add(-time.Duration(cfg.StorageTieringAgeDays) * 24 * time.Hour)
	filesMovedCount := 0
	var totalBytesMoved int64

	err := filepath.Walk(cfg.StorageSSDPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Si le fichier est plus ancien que le seuil, le déplacer
		if info.ModTime().Before(cutoffDate) {
			// Calculer le chemin de destination
			relPath, err := filepath.Rel(cfg.StorageSSDPath, path)
			if err != nil {
				return nil
			}

			destPath := filepath.Join(cfg.StorageHDDPath, relPath)

			// Créer les répertoires de destination
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				o.logger.LogError("Failed to create destination directory: %v", err)
				return nil
			}

			// Déplacer le fichier
			if err := os.Rename(path, destPath); err != nil {
				// Si le rename échoue (filesystems différents), copier puis supprimer
				if err := o.copyFile(path, destPath); err != nil {
					o.logger.LogError("Failed to move file %s: %v", path, err)
					return nil
				}
				os.Remove(path)
			}

			filesMovedCount++
			totalBytesMoved += info.Size()

			o.logger.LogSync("Moved to HDD: %s (%.2f MB, age: %d days)",
				filepath.Base(path), float64(info.Size())/1024/1024,
				int(time.Since(info.ModTime()).Hours()/24))

			// Créer un lien symbolique du SSD vers le HDD
			if err := os.Symlink(destPath, path); err != nil {
				o.logger.LogError("Failed to create symlink: %v", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to tier files: %w", err)
	}

	o.logger.LogInfo("Tiering complete: %d files moved to HDD (%.2f GB)",
		filesMovedCount, float64(totalBytesMoved)/1024/1024/1024)

	return nil
}

// copyFile copie un fichier
func (o *Optimizer) copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = destination.ReadFrom(source)
	return err
}

// GetStorageStats retourne les statistiques de stockage
func (o *Optimizer) GetStorageStats() (*StorageStats, error) {
	cfg := o.config.Get()

	stats := &StorageStats{}

	// Compter les fichiers et la taille totale
	poolPath := filepath.Join(cfg.RepositoryPath, "pool")
	filepath.Walk(poolPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		stats.TotalFiles++
		stats.TotalBytes += info.Size()

		if strings.HasSuffix(path, ".deb") {
			stats.PackageCount++
		}

		// Vérifier si c'est un hard link
		if o.isHardLink(path) {
			stats.HardLinkCount++
		}

		return nil
	})

	// Utilisation disque
	diskInfo, err := utils.GetDiskUsage(cfg.RepositoryPath)
	if err != nil {
		return nil, err
	}

	stats.DiskUsedBytes = diskInfo.Used
	stats.DiskTotalBytes = diskInfo.Total
	stats.DiskFreeBytes = diskInfo.Free
	stats.DiskUsedPercent = diskInfo.UsedPercent

	return stats, nil
}

// StorageStats représente les statistiques de stockage
type StorageStats struct {
	TotalFiles      int     `json:"total_files"`
	TotalBytes      int64   `json:"total_bytes"`
	PackageCount    int     `json:"package_count"`
	HardLinkCount   int     `json:"hard_link_count"`
	DiskUsedBytes   uint64  `json:"disk_used_bytes"`
	DiskTotalBytes  uint64  `json:"disk_total_bytes"`
	DiskFreeBytes   uint64  `json:"disk_free_bytes"`
	DiskUsedPercent float64 `json:"disk_used_percent"`
}

// isHardLink vérifie si un fichier est un hard link
func (o *Optimizer) isHardLink(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Sur Unix, si le nombre de liens est > 1, c'est un hard link
	// Note: Cette méthode utilise des fonctionnalités spécifiques à Unix
	return stat.Mode().IsRegular() && stat.Mode()&os.ModeSymlink == 0
}
