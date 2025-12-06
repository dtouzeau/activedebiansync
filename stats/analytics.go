package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// PackageAccessRecord enregistre un accès à un package
type PackageAccessRecord struct {
	PackageName string    `json:"package_name"`
	Path        string    `json:"path"`
	ClientIP    string    `json:"client_ip"`
	BytesSent   int64     `json:"bytes_sent"`
	Timestamp   time.Time `json:"timestamp"`
	Duration    int64     `json:"duration_ms"` // En millisecondes
}

// BandwidthRecord enregistre l'utilisation de la bande passante
type BandwidthRecord struct {
	Timestamp time.Time `json:"timestamp"`
	BytesSent int64     `json:"bytes_sent"`
	Requests  int       `json:"requests"`
}

// DiskPrediction représente une prédiction d'utilisation disque
type DiskPrediction struct {
	CurrentUsageGB    float64   `json:"current_usage_gb"`
	PredictedGB       float64   `json:"predicted_gb"`
	PredictionDate    time.Time `json:"prediction_date"`
	GrowthRateGBPerDay float64   `json:"growth_rate_gb_per_day"`
	DaysUntilFull     int       `json:"days_until_full"`
	TotalCapacityGB   float64   `json:"total_capacity_gb"`
}

// Analytics gère les statistiques avancées
type Analytics struct {
	packageAccess   []PackageAccessRecord
	bandwidthHourly map[string]*BandwidthRecord // key: YYYY-MM-DD-HH
	bandwidthDaily  map[string]*BandwidthRecord // key: YYYY-MM-DD
	diskHistory     []DiskUsagePoint
	statsFile       string
	mu              sync.RWMutex
}

// DiskUsagePoint représente un point de mesure d'utilisation disque
type DiskUsagePoint struct {
	Timestamp time.Time `json:"timestamp"`
	UsedGB    float64   `json:"used_gb"`
	TotalGB   float64   `json:"total_gb"`
}

// NewAnalytics crée une nouvelle instance d'Analytics
func NewAnalytics(statsFile string) *Analytics {
	a := &Analytics{
		packageAccess:   make([]PackageAccessRecord, 0),
		bandwidthHourly: make(map[string]*BandwidthRecord),
		bandwidthDaily:  make(map[string]*BandwidthRecord),
		diskHistory:     make([]DiskUsagePoint, 0),
		statsFile:       statsFile,
	}

	// Charger les stats existantes
	a.Load()

	return a
}

// RecordPackageAccess enregistre un accès à un package
func (a *Analytics) RecordPackageAccess(record PackageAccessRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()

	record.Timestamp = time.Now()
	a.packageAccess = append(a.packageAccess, record)

	// Mettre à jour les statistiques de bande passante
	hourKey := record.Timestamp.Format("2006-01-02-15")
	dayKey := record.Timestamp.Format("2006-01-02")

	// Bande passante horaire
	if _, exists := a.bandwidthHourly[hourKey]; !exists {
		a.bandwidthHourly[hourKey] = &BandwidthRecord{
			Timestamp: record.Timestamp,
		}
	}
	a.bandwidthHourly[hourKey].BytesSent += record.BytesSent
	a.bandwidthHourly[hourKey].Requests++

	// Bande passante journalière
	if _, exists := a.bandwidthDaily[dayKey]; !exists {
		a.bandwidthDaily[dayKey] = &BandwidthRecord{
			Timestamp: record.Timestamp,
		}
	}
	a.bandwidthDaily[dayKey].BytesSent += record.BytesSent
	a.bandwidthDaily[dayKey].Requests++

	// Limiter la taille en mémoire (garder les 10000 derniers accès)
	if len(a.packageAccess) > 10000 {
		a.packageAccess = a.packageAccess[len(a.packageAccess)-10000:]
	}
}

// GetTopPackages retourne les N packages les plus téléchargés
func (a *Analytics) GetTopPackages(n int, since time.Time) []PackageStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Agréger les statistiques par package
	packageMap := make(map[string]*PackageStats)

	for _, record := range a.packageAccess {
		if record.Timestamp.Before(since) {
			continue
		}

		if _, exists := packageMap[record.PackageName]; !exists {
			packageMap[record.PackageName] = &PackageStats{
				PackageName: record.PackageName,
			}
		}

		packageMap[record.PackageName].TotalDownloads++
		packageMap[record.PackageName].TotalBytes += record.BytesSent
		packageMap[record.PackageName].UniqueIPs[record.ClientIP] = true
	}

	// Convertir en slice
	stats := make([]PackageStats, 0, len(packageMap))
	for _, ps := range packageMap {
		ps.UniqueClients = len(ps.UniqueIPs)
		stats = append(stats, *ps)
	}

	// Trier par nombre de téléchargements
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].TotalDownloads > stats[j].TotalDownloads
	})

	// Limiter à N résultats
	if len(stats) > n {
		stats = stats[:n]
	}

	return stats
}

// PackageStats représente les statistiques d'un package
type PackageStats struct {
	PackageName    string         `json:"package_name"`
	TotalDownloads int            `json:"total_downloads"`
	TotalBytes     int64          `json:"total_bytes"`
	UniqueClients  int            `json:"unique_clients"`
	UniqueIPs      map[string]bool `json:"-"`
}

// GetBandwidthByHour retourne la bande passante par heure
func (a *Analytics) GetBandwidthByHour(since time.Time) []BandwidthRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var records []BandwidthRecord
	for _, record := range a.bandwidthHourly {
		if record.Timestamp.After(since) {
			records = append(records, *record)
		}
	}

	// Trier par timestamp
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	return records
}

// GetBandwidthByDay retourne la bande passante par jour
func (a *Analytics) GetBandwidthByDay(since time.Time) []BandwidthRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var records []BandwidthRecord
	for _, record := range a.bandwidthDaily {
		if record.Timestamp.After(since) {
			records = append(records, *record)
		}
	}

	// Trier par timestamp
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	return records
}

// DetectAnomalies détecte les anomalies dans le trafic
func (a *Analytics) DetectAnomalies() []Anomaly {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var anomalies []Anomaly

	// Calculer la moyenne et l'écart-type des requêtes par heure
	hourlyRecords := make([]BandwidthRecord, 0, len(a.bandwidthHourly))
	for _, record := range a.bandwidthHourly {
		hourlyRecords = append(hourlyRecords, *record)
	}

	if len(hourlyRecords) < 10 {
		// Pas assez de données
		return anomalies
	}

	// Calculer la moyenne
	var sumRequests int64
	var sumBytes int64
	for _, record := range hourlyRecords {
		sumRequests += int64(record.Requests)
		sumBytes += record.BytesSent
	}
	avgRequests := float64(sumRequests) / float64(len(hourlyRecords))
	avgBytes := float64(sumBytes) / float64(len(hourlyRecords))

	// Calculer l'écart-type
	var varianceRequests float64
	var varianceBytes float64
	for _, record := range hourlyRecords {
		diffReq := float64(record.Requests) - avgRequests
		diffBytes := float64(record.BytesSent) - avgBytes
		varianceRequests += diffReq * diffReq
		varianceBytes += diffBytes * diffBytes
	}
	stdDevRequests := varianceRequests / float64(len(hourlyRecords))
	stdDevBytes := varianceBytes / float64(len(hourlyRecords))

	// Détecter les anomalies (> 3 écarts-types)
	threshold := 3.0
	for _, record := range hourlyRecords {
		if float64(record.Requests) > avgRequests+threshold*stdDevRequests {
			anomalies = append(anomalies, Anomaly{
				Timestamp:   record.Timestamp,
				Type:        "high_traffic_requests",
				Description: fmt.Sprintf("Pic de requêtes: %d (moyenne: %.0f)", record.Requests, avgRequests),
				Value:       float64(record.Requests),
				Threshold:   avgRequests + threshold*stdDevRequests,
			})
		}

		if float64(record.BytesSent) > avgBytes+threshold*stdDevBytes {
			anomalies = append(anomalies, Anomaly{
				Timestamp:   record.Timestamp,
				Type:        "high_traffic_bandwidth",
				Description: fmt.Sprintf("Pic de bande passante: %.2f MB (moyenne: %.2f MB)", float64(record.BytesSent)/1024/1024, avgBytes/1024/1024),
				Value:       float64(record.BytesSent),
				Threshold:   avgBytes + threshold*stdDevBytes,
			})
		}
	}

	return anomalies
}

// Anomaly représente une anomalie détectée
type Anomaly struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
}

// RecordDiskUsage enregistre un point de mesure d'utilisation disque
func (a *Analytics) RecordDiskUsage(usedGB, totalGB float64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	point := DiskUsagePoint{
		Timestamp: time.Now(),
		UsedGB:    usedGB,
		TotalGB:   totalGB,
	}

	a.diskHistory = append(a.diskHistory, point)

	// Garder uniquement les 90 derniers jours
	if len(a.diskHistory) > 90*24 { // 90 jours * 24 mesures par jour
		a.diskHistory = a.diskHistory[len(a.diskHistory)-90*24:]
	}
}

// PredictDiskUsage prédit l'utilisation future du disque
func (a *Analytics) PredictDiskUsage(daysAhead int) (*DiskPrediction, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.diskHistory) < 2 {
		return nil, fmt.Errorf("not enough data for prediction")
	}

	// Régression linéaire simple
	var sumX, sumY, sumXY, sumX2 float64
	n := float64(len(a.diskHistory))

	for i, point := range a.diskHistory {
		x := float64(i)
		y := point.UsedGB
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// Calculer la pente (taux de croissance)
	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
	intercept := (sumY - slope*sumX) / n

	// Prédire l'utilisation future
	futureX := float64(len(a.diskHistory) + daysAhead*24) // Convertir jours en heures
	predictedGB := slope*futureX + intercept

	// Calculer le nombre de jours avant saturation
	currentUsage := a.diskHistory[len(a.diskHistory)-1].UsedGB
	totalCapacity := a.diskHistory[len(a.diskHistory)-1].TotalGB
	remainingGB := totalCapacity - currentUsage

	daysUntilFull := 0
	if slope > 0 {
		hoursUntilFull := remainingGB / (slope * 24) // slope par heure * 24
		daysUntilFull = int(hoursUntilFull / 24)
	}

	return &DiskPrediction{
		CurrentUsageGB:    currentUsage,
		PredictedGB:       predictedGB,
		PredictionDate:    time.Now().Add(time.Duration(daysAhead) * 24 * time.Hour),
		GrowthRateGBPerDay: slope * 24, // Convertir en GB/jour
		DaysUntilFull:     daysUntilFull,
		TotalCapacityGB:   totalCapacity,
	}, nil
}

// Save sauvegarde les statistiques sur disque
func (a *Analytics) Save() error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Créer le répertoire si nécessaire
	dir := filepath.Dir(a.statsFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create stats directory: %w", err)
	}

	data := struct {
		PackageAccess   []PackageAccessRecord           `json:"package_access"`
		BandwidthHourly map[string]*BandwidthRecord     `json:"bandwidth_hourly"`
		BandwidthDaily  map[string]*BandwidthRecord     `json:"bandwidth_daily"`
		DiskHistory     []DiskUsagePoint                `json:"disk_history"`
	}{
		PackageAccess:   a.packageAccess,
		BandwidthHourly: a.bandwidthHourly,
		BandwidthDaily:  a.bandwidthDaily,
		DiskHistory:     a.diskHistory,
	}

	file, err := os.Create(a.statsFile)
	if err != nil {
		return fmt.Errorf("failed to create stats file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode stats: %w", err)
	}

	return nil
}

// Load charge les statistiques depuis le disque
func (a *Analytics) Load() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := os.Stat(a.statsFile); os.IsNotExist(err) {
		// Pas de fichier, c'est ok
		return nil
	}

	file, err := os.Open(a.statsFile)
	if err != nil {
		return fmt.Errorf("failed to open stats file: %w", err)
	}
	defer file.Close()

	var data struct {
		PackageAccess   []PackageAccessRecord       `json:"package_access"`
		BandwidthHourly map[string]*BandwidthRecord `json:"bandwidth_hourly"`
		BandwidthDaily  map[string]*BandwidthRecord `json:"bandwidth_daily"`
		DiskHistory     []DiskUsagePoint            `json:"disk_history"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("failed to decode stats: %w", err)
	}

	a.packageAccess = data.PackageAccess
	a.bandwidthHourly = data.BandwidthHourly
	a.bandwidthDaily = data.BandwidthDaily
	a.diskHistory = data.DiskHistory

	return nil
}

// CleanupOldData supprime les données plus anciennes que la période spécifiée
func (a *Analytics) CleanupOldData(retentionDays int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	// Nettoyer les accès aux packages
	newAccess := make([]PackageAccessRecord, 0)
	for _, record := range a.packageAccess {
		if record.Timestamp.After(cutoff) {
			newAccess = append(newAccess, record)
		}
	}
	a.packageAccess = newAccess

	// Nettoyer la bande passante horaire
	for key, record := range a.bandwidthHourly {
		if record.Timestamp.Before(cutoff) {
			delete(a.bandwidthHourly, key)
		}
	}

	// Nettoyer la bande passante journalière (garder plus longtemps)
	cutoffDaily := time.Now().Add(-time.Duration(retentionDays*3) * 24 * time.Hour)
	for key, record := range a.bandwidthDaily {
		if record.Timestamp.Before(cutoffDaily) {
			delete(a.bandwidthDaily, key)
		}
	}
}
