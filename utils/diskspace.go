package utils

import (
	"fmt"
	"github.com/shirou/gopsutil/v3/disk"
)

// DiskSpaceInfo contient les informations d'espace disque
type DiskSpaceInfo struct {
	Total       uint64  `json:"total_bytes"`
	Used        uint64  `json:"used_bytes"`
	Free        uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// GetDiskUsage retourne les informations d'utilisation du disque pour un chemin
func GetDiskUsage(path string) (*DiskSpaceInfo, error) {
	usage, err := disk.Usage(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	return &DiskSpaceInfo{
		Total:       usage.Total,
		Used:        usage.Used,
		Free:        usage.Free,
		UsedPercent: usage.UsedPercent,
	}, nil
}

// CheckDiskSpace vérifie si l'espace disque dépasse le seuil
func CheckDiskSpace(path string, maxPercent int) (bool, *DiskSpaceInfo, error) {
	info, err := GetDiskUsage(path)
	if err != nil {
		return false, nil, err
	}

	return info.UsedPercent >= float64(maxPercent), info, nil
}

// FormatBytes formate les octets en format lisible
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
