package metrics

import (
	"activedebiansync/config"
	"activedebiansync/server"
	"activedebiansync/sync"
	"activedebiansync/utils"
	"os"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusMetrics contient tous les collecteurs Prometheus
type PrometheusMetrics struct {
	config     *config.Config
	syncer     SyncStatsProvider
	httpServer ServerStatsProvider

	// Métriques de synchronisation
	syncDuration      prometheus.Histogram
	syncFilesTotal    prometheus.Counter
	syncBytesTotal    prometheus.Counter
	syncErrorsTotal   prometheus.Counter
	syncLastTimestamp prometheus.Gauge
	syncRunning       prometheus.Gauge

	// Métriques serveur HTTP
	httpRequestsTotal  prometheus.Counter
	httpBytesSentTotal prometheus.Counter
	httpClientsActive  prometheus.Gauge

	// Métriques disque
	diskUsageBytes   prometheus.Gauge
	diskUsagePercent prometheus.Gauge
	diskTotalBytes   prometheus.Gauge
	diskFreeBytes    prometheus.Gauge

	// Métriques packages
	packageCount prometheus.Gauge

	// Métriques système
	uptime prometheus.Gauge
	up     prometheus.Gauge
}

// SyncStatsProvider interface pour obtenir les stats de sync
type SyncStatsProvider interface {
	GetStats() *sync.SyncStats
}

// ServerStatsProvider interface pour obtenir les stats du serveur
type ServerStatsProvider interface {
	GetStats() *server.ServerStats
	GetClients() []server.ClientInfo
}

// NewPrometheusMetrics crée une nouvelle instance de métriques Prometheus
func NewPrometheusMetrics(cfg *config.Config, syncer SyncStatsProvider, httpServer ServerStatsProvider) *PrometheusMetrics {
	namespace := "activedebiansync"

	pm := &PrometheusMetrics{
		config:     cfg,
		syncer:     syncer,
		httpServer: httpServer,

		// Synchronisation
		syncDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "sync_duration_seconds",
			Help:      "Duration of repository synchronization operations",
			Buckets:   prometheus.ExponentialBuckets(60, 2, 10), // 60s à ~17h
		}),

		syncFilesTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sync_files_total",
			Help:      "Total number of files synchronized",
		}),

		syncBytesTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sync_bytes_total",
			Help:      "Total number of bytes synchronized",
		}),

		syncErrorsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sync_errors_total",
			Help:      "Total number of synchronization errors",
		}),

		syncLastTimestamp: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sync_last_timestamp",
			Help:      "Timestamp of last successful synchronization",
		}),

		syncRunning: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sync_running",
			Help:      "Whether a synchronization is currently running (1 = yes, 0 = no)",
		}),

		// HTTP Server
		httpRequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests served",
		}),

		httpBytesSentTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_bytes_sent_total",
			Help:      "Total number of bytes sent via HTTP",
		}),

		httpClientsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "http_clients_active",
			Help:      "Number of active HTTP clients",
		}),

		// Disque
		diskUsageBytes: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "disk_usage_bytes",
			Help:      "Disk space used by the repository in bytes",
		}),

		diskUsagePercent: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "disk_usage_percent",
			Help:      "Disk space used percentage",
		}),

		diskTotalBytes: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "disk_total_bytes",
			Help:      "Total disk space in bytes",
		}),

		diskFreeBytes: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "disk_free_bytes",
			Help:      "Free disk space in bytes",
		}),

		// Packages
		packageCount: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "package_count",
			Help:      "Number of custom packages in the repository",
		}),

		// Système
		uptime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "uptime_seconds",
			Help:      "Service uptime in seconds",
		}),

		up: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Service is up and running (always 1)",
		}),
	}

	// Service is up
	pm.up.Set(1)

	return pm
}

// UpdateMetrics met à jour toutes les métriques avec les valeurs actuelles
func (pm *PrometheusMetrics) UpdateMetrics(startTime int64) {
	// Mettre à jour uptime
	pm.uptime.Set(float64(startTime))

	// Stats de sync
	if pm.syncer != nil {
		stats := pm.syncer.GetStats()

		// Set counters based on current values
		// Note: Prometheus counters can only increase, so we set them to the total
		pm.syncFilesTotal.Add(float64(stats.TotalFiles) - pm.getCurrentCounterValue(pm.syncFilesTotal))
		pm.syncBytesTotal.Add(float64(stats.TotalBytes) - pm.getCurrentCounterValue(pm.syncBytesTotal))
		pm.syncErrorsTotal.Add(float64(stats.FailedFiles) - pm.getCurrentCounterValue(pm.syncErrorsTotal))

		// Gauges
		if stats.IsRunning {
			pm.syncRunning.Set(1)
		} else {
			pm.syncRunning.Set(0)
		}

		if !stats.LastSyncEnd.IsZero() {
			pm.syncLastTimestamp.Set(float64(stats.LastSyncEnd.Unix()))
		}
	}

	// Stats serveur HTTP
	if pm.httpServer != nil {
		serverStats := pm.httpServer.GetStats()

		pm.httpRequestsTotal.Add(float64(serverStats.TotalRequests) - pm.getCurrentCounterValue(pm.httpRequestsTotal))
		pm.httpBytesSentTotal.Add(float64(serverStats.TotalBytesSent) - pm.getCurrentCounterValue(pm.httpBytesSentTotal))

		// Clients actifs
		clients := pm.httpServer.GetClients()
		pm.httpClientsActive.Set(float64(len(clients)))
	}

	// Stats disque
	cfg := pm.config.Get()
	diskInfo, err := utils.GetDiskUsage(cfg.RepositoryPath)
	if err == nil {
		pm.diskUsageBytes.Set(float64(diskInfo.Used))
		pm.diskUsagePercent.Set(diskInfo.UsedPercent)
		pm.diskTotalBytes.Set(float64(diskInfo.Total))
		pm.diskFreeBytes.Set(float64(diskInfo.Free))
	}

	// Compter les packages personnalisés
	pm.updatePackageCount()
}

// getCurrentCounterValue est un helper pour éviter les décréments de compteur
// Cette fonction retourne toujours 0 car on ne peut pas lire la valeur d'un compteur Prometheus
func (pm *PrometheusMetrics) getCurrentCounterValue(counter prometheus.Counter) float64 {
	return 0 // Les compteurs sont toujours additionnés depuis leur création
}

// updatePackageCount compte les packages personnalisés dans le pool
func (pm *PrometheusMetrics) updatePackageCount() {
	cfg := pm.config.Get()
	poolPath := filepath.Join(cfg.RepositoryPath, "pool")

	count := 0
	filepath.Walk(poolPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Compter les fichiers .deb
		if !info.IsDir() && filepath.Ext(path) == ".deb" {
			count++
		}
		return nil
	})

	pm.packageCount.Set(float64(count))
}

// RecordSyncDuration enregistre la durée d'une synchronisation
func (pm *PrometheusMetrics) RecordSyncDuration(seconds float64) {
	pm.syncDuration.Observe(seconds)
}

// IncrementSyncFiles incrémente le compteur de fichiers synchronisés
func (pm *PrometheusMetrics) IncrementSyncFiles(count int64) {
	pm.syncFilesTotal.Add(float64(count))
}

// IncrementSyncBytes incrémente le compteur d'octets synchronisés
func (pm *PrometheusMetrics) IncrementSyncBytes(bytes int64) {
	pm.syncBytesTotal.Add(float64(bytes))
}

// IncrementSyncErrors incrémente le compteur d'erreurs de sync
func (pm *PrometheusMetrics) IncrementSyncErrors(count int64) {
	pm.syncErrorsTotal.Add(float64(count))
}

// IncrementHTTPRequests incrémente le compteur de requêtes HTTP
func (pm *PrometheusMetrics) IncrementHTTPRequests(count int64) {
	pm.httpRequestsTotal.Add(float64(count))
}

// IncrementHTTPBytesSent incrémente le compteur d'octets envoyés
func (pm *PrometheusMetrics) IncrementHTTPBytesSent(bytes int64) {
	pm.httpBytesSentTotal.Add(float64(bytes))
}
