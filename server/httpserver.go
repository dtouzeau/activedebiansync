package server

import (
	"activedebiansync/config"
	"activedebiansync/stats"
	"activedebiansync/utils"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SyncChecker est une interface pour vérifier si une sync est en cours
type SyncChecker interface {
	IsRunning() bool
}

// HTTPServer gère le serveur HTTP/HTTPS pour servir le dépôt APT
type HTTPServer struct {
	config      *config.Config
	logger      *utils.Logger
	httpServer  *http.Server
	httpsServer *http.Server
	stats       *ServerStats
	clients     *ClientTracker
	syncChecker SyncChecker
	analytics   *stats.Analytics
	wg          sync.WaitGroup
}

// ServerStats contient les statistiques du serveur HTTP
type ServerStats struct {
	TotalRequests   int64 `json:"total_requests"`
	TotalBytesSent  int64 `json:"total_bytes_sent"`
	ActiveClients   int32 `json:"active_clients"`
}

// ClientInfo contient les informations sur un client connecté
type ClientInfo struct {
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	RequestCount  int64     `json:"request_count"`
	BytesReceived int64     `json:"bytes_received"`
}

// ClientTracker suit les clients qui se connectent
type ClientTracker struct {
	clients map[string]*ClientInfo
	mu      sync.RWMutex
}

// NewClientTracker crée un nouveau tracker de clients
func NewClientTracker() *ClientTracker {
	return &ClientTracker{
		clients: make(map[string]*ClientInfo),
	}
}

// Track enregistre un accès client
func (ct *ClientTracker) Track(ip string, bytesReceived int64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	client, exists := ct.clients[ip]
	if !exists {
		// Résoudre le hostname (avec timeout)
		hostname := ip
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			hostname = names[0]
		}

		client = &ClientInfo{
			IP:        ip,
			Hostname:  hostname,
			FirstSeen: time.Now(),
		}
		ct.clients[ip] = client
	}

	client.LastSeen = time.Now()
	client.RequestCount++
	client.BytesReceived += bytesReceived
}

// GetClients retourne la liste des clients
func (ct *ClientTracker) GetClients() []ClientInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]ClientInfo, 0, len(ct.clients))
	for _, client := range ct.clients {
		result = append(result, *client)
	}
	return result
}

// NewHTTPServer crée un nouveau serveur HTTP
func NewHTTPServer(cfg *config.Config, logger *utils.Logger) *HTTPServer {
	return &HTTPServer{
		config:      cfg,
		logger:      logger,
		stats:       &ServerStats{},
		clients:     NewClientTracker(),
		syncChecker: nil, // Sera défini via SetSyncChecker
	}
}

// SetSyncChecker définit le SyncChecker pour vérifier si une sync est en cours
func (s *HTTPServer) SetSyncChecker(checker SyncChecker) {
	s.syncChecker = checker
}

// SetAnalytics définit le module d'analytics pour l'enregistrement des accès
func (s *HTTPServer) SetAnalytics(analytics *stats.Analytics) {
	s.analytics = analytics
}

// Start démarre les serveurs HTTP/HTTPS
func (s *HTTPServer) Start(ctx context.Context) error {
	cfg := s.config.Get()

	// Créer le handler avec logging
	handler := s.createLoggingHandler(http.FileServer(http.Dir(cfg.RepositoryPath)))

	// Démarrer le serveur HTTP
	if cfg.HTTPEnabled {
		s.httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler: handler,
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.logger.LogInfo("Starting HTTP server on port %d", cfg.HTTPPort)
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.LogError("HTTP server error: %v", err)
			}
		}()
	}

	// Démarrer le serveur HTTPS
	if cfg.HTTPSEnabled {
		// Vérifier que les certificats existent
		if _, err := os.Stat(cfg.TLSCertFile); os.IsNotExist(err) {
			s.logger.LogError("TLS certificate not found: %s", cfg.TLSCertFile)
		} else if _, err := os.Stat(cfg.TLSKeyFile); os.IsNotExist(err) {
			s.logger.LogError("TLS key not found: %s", cfg.TLSKeyFile)
		} else {
			s.httpsServer = &http.Server{
				Addr:    fmt.Sprintf(":%d", cfg.HTTPSPort),
				Handler: handler,
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.logger.LogInfo("Starting HTTPS server on port %d", cfg.HTTPSPort)
				if err := s.httpsServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
					s.logger.LogError("HTTPS server error: %v", err)
				}
			}()
		}
	}

	// Attendre l'arrêt
	<-ctx.Done()
	return s.Stop()
}

// Stop arrête les serveurs
func (s *HTTPServer) Stop() error {
	s.logger.LogInfo("Stopping HTTP/HTTPS servers")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.LogError("Failed to shutdown HTTP server: %v", err)
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			s.logger.LogError("Failed to shutdown HTTPS server: %v", err)
		}
	}

	s.wg.Wait()
	return nil
}

// createLoggingHandler crée un handler qui log les accès
func (s *HTTPServer) createLoggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.config.Get()

		// Bloquer les clients si une synchronisation est en cours
		if cfg.BlockClientsDuringSync && s.syncChecker != nil && s.syncChecker.IsRunning() {
			clientIP := r.RemoteAddr
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}
			s.logger.LogAccess(clientIP, r.Method, r.RequestURI, http.StatusServiceUnavailable, 0)
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("503 Service Unavailable - Repository synchronization in progress\n"))
			return
		}

		start := time.Now()

		// Incrémenter les clients actifs
		atomic.AddInt32(&s.stats.ActiveClients, 1)
		defer atomic.AddInt32(&s.stats.ActiveClients, -1)

		// Wrapper pour capturer le status code et les bytes envoyés
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Appeler le handler suivant
		next.ServeHTTP(wrapped, r)

		// Extraire l'IP du client
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// Vérifier X-Forwarded-For pour les proxies
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = xff
		}

		// Calculer la durée
		duration := time.Since(start)

		// Logger l'accès
		s.logger.LogAccess(clientIP, r.Method, r.URL.Path, wrapped.statusCode, wrapped.bytesWritten)

		// Mettre à jour les statistiques
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		atomic.AddInt64(&s.stats.TotalBytesSent, wrapped.bytesWritten)

		// Suivre le client
		s.clients.Track(clientIP, wrapped.bytesWritten)

		// Enregistrer l'accès dans les analytics si disponible et si c'est une requête réussie
		if s.analytics != nil && wrapped.statusCode == http.StatusOK && wrapped.bytesWritten > 0 {
			// Extraire le nom du package depuis le chemin (pour les fichiers .deb)
			packageName := s.extractPackageName(r.URL.Path)
			if packageName != "" {
				record := stats.PackageAccessRecord{
					PackageName: packageName,
					Path:        r.URL.Path,
					ClientIP:    clientIP,
					BytesSent:   wrapped.bytesWritten,
					Duration:    duration.Milliseconds(),
				}
				s.analytics.RecordPackageAccess(record)
			}
		}

		// Log détaillé pour les requêtes lentes
		if duration > 5*time.Second {
			s.logger.LogInfo("Slow request: %s %s from %s took %s", r.Method, r.URL.Path, clientIP, duration)
		}
	})
}

// extractPackageName extrait le nom du package depuis un chemin de fichier
func (s *HTTPServer) extractPackageName(path string) string {
	// Extraire le nom de base du fichier
	filename := filepath.Base(path)

	// Vérifier si c'est un fichier .deb
	if strings.HasSuffix(filename, ".deb") {
		// Format typique: package_version_arch.deb
		// Ex: vim_8.2.0-1_amd64.deb -> vim
		parts := strings.Split(filename, "_")
		if len(parts) > 0 {
			return parts[0]
		}
		return filename
	}

	// Pour les fichiers Packages.gz, Packages.xz, etc.
	if strings.Contains(path, "/binary-") {
		// Retourner le composant (main, contrib, etc.) + architecture
		return path
	}

	// Pour les autres fichiers d'index (Release, InRelease, etc.)
	if strings.HasSuffix(filename, "Release") || strings.HasSuffix(filename, "InRelease") ||
		strings.HasSuffix(filename, "Packages.gz") || strings.HasSuffix(filename, "Packages.xz") {
		return filename
	}

	return ""
}

// GetStats retourne les statistiques du serveur
func (s *HTTPServer) GetStats() *ServerStats {
	return &ServerStats{
		TotalRequests:  atomic.LoadInt64(&s.stats.TotalRequests),
		TotalBytesSent: atomic.LoadInt64(&s.stats.TotalBytesSent),
		ActiveClients:  atomic.LoadInt32(&s.stats.ActiveClients),
	}
}

// LoadStats charge les statistiques depuis des valeurs persistées
func (s *HTTPServer) LoadStats(totalRequests, totalBytesSent int64) {
	atomic.StoreInt64(&s.stats.TotalRequests, totalRequests)
	atomic.StoreInt64(&s.stats.TotalBytesSent, totalBytesSent)
}

// LoadClients charge les clients depuis des données persistées
func (s *HTTPServer) LoadClients(clients []ClientInfo) {
	s.clients.mu.Lock()
	defer s.clients.mu.Unlock()

	for _, client := range clients {
		s.clients.clients[client.IP] = &ClientInfo{
			IP:            client.IP,
			Hostname:      client.Hostname,
			FirstSeen:     client.FirstSeen,
			LastSeen:      client.LastSeen,
			RequestCount:  client.RequestCount,
			BytesReceived: client.BytesReceived,
		}
	}
}

// GetClients retourne la liste des clients
func (s *HTTPServer) GetClients() []ClientInfo {
	return s.clients.GetClients()
}

// responseWriter wrapper pour capturer le status code et les bytes écrits
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}
