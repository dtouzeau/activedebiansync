package server

import (
	"activedebiansync/config"
	"activedebiansync/database"
	"activedebiansync/stats"
	"activedebiansync/utils"
	"context"
	"fmt"
	"io"
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
	securityDB  *database.SecurityDB
	clientsDB   *database.ClientsDB
	wg          sync.WaitGroup
}

// ServerStats contient les statistiques du serveur HTTP
type ServerStats struct {
	TotalRequests  int64 `json:"total_requests"`
	TotalBytesSent int64 `json:"total_bytes_sent"`
	ActiveClients  int32 `json:"active_clients"`
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

// SetSecurityDB définit la base de données de sécurité pour le contrôle d'accès
func (s *HTTPServer) SetSecurityDB(securityDB *database.SecurityDB) {
	s.securityDB = securityDB
}

// GetSecurityDB retourne la base de données de sécurité
func (s *HTTPServer) GetSecurityDB() *database.SecurityDB {
	return s.securityDB
}

// SetClientsDB définit la base de données des clients pour les statistiques
func (s *HTTPServer) SetClientsDB(clientsDB *database.ClientsDB) {
	s.clientsDB = clientsDB
}

// GetClientsDB retourne la base de données des clients
func (s *HTTPServer) GetClientsDB() *database.ClientsDB {
	return s.clientsDB
}

// Start démarre les serveurs HTTP/HTTPS
func (s *HTTPServer) Start(ctx context.Context) error {
	cfg := s.config.Get()

	// Créer le file server de base
	fileServer := http.FileServer(http.Dir(cfg.RepositoryPath))

	// Créer le handler HTTP avec logging (isHTTPS = false)
	httpHandler := s.createLoggingHandler(fileServer)

	// Démarrer le serveur HTTP
	if cfg.HTTPEnabled {
		s.httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler: httpHandler,
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
			// Créer le handler HTTPS avec logging (isHTTPS = true)
			httpsHandler := s.createLoggingHandlerHTTPS(fileServer)

			s.httpsServer = &http.Server{
				Addr:    fmt.Sprintf(":%d", cfg.HTTPSPort),
				Handler: httpsHandler,
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
	return s.createLoggingHandlerWithHTTPS(next, false)
}

// createLoggingHandlerHTTPS crée un handler pour HTTPS
func (s *HTTPServer) createLoggingHandlerHTTPS(next http.Handler) http.Handler {
	return s.createLoggingHandlerWithHTTPS(next, true)
}

// createLoggingHandlerWithHTTPS crée un handler qui log les accès avec support HTTPS
func (s *HTTPServer) createLoggingHandlerWithHTTPS(next http.Handler, isHTTPS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.config.Get()

		// Extraire l'IP du client
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// Vérifier X-Forwarded-For pour les proxies
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Prendre la première IP (client original)
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				clientIP = strings.TrimSpace(parts[0])
			}
		}

		userAgent := r.Header.Get("User-Agent")

		// Vérifier les règles de sécurité
		var bandwidthLimit int64
		if s.securityDB != nil {
			result := s.securityDB.CheckAccess(clientIP, userAgent, isHTTPS)
			if result.Denied {
				s.logger.LogAccess(clientIP, r.Method, r.RequestURI, http.StatusForbidden, 0)
				s.logger.LogInfo("Access denied for %s (UA: %s): %s", clientIP, userAgent, result.Reason)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403 Forbidden - Access denied by security policy\n"))
				return
			}
			bandwidthLimit = result.BandwidthLimit
		}

		// Bloquer les clients si une synchronisation est en cours
		if cfg.BlockClientsDuringSync && s.syncChecker != nil && s.syncChecker.IsRunning() {
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
		// Si bandwidth limit, utiliser le rate limited writer
		var wrapped *responseWriter
		if bandwidthLimit > 0 {
			wrapped = &responseWriter{
				ResponseWriter: w,
				statusCode:     200,
				rateLimiter:    newRateLimiter(bandwidthLimit),
			}
		} else {
			wrapped = &responseWriter{ResponseWriter: w, statusCode: 200}
		}

		// Appeler le handler suivant
		next.ServeHTTP(wrapped, r)

		// Calculer la durée
		duration := time.Since(start)

		// Logger l'accès
		s.logger.LogAccess(clientIP, r.Method, r.URL.Path, wrapped.statusCode, wrapped.bytesWritten)

		// Mettre à jour les statistiques
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		atomic.AddInt64(&s.stats.TotalBytesSent, wrapped.bytesWritten)

		// Suivre le client
		s.clients.Track(clientIP, wrapped.bytesWritten)

		// Enregistrer dans la base de données clients si disponible et si c'est une requête réussie
		if s.clientsDB != nil && wrapped.statusCode == http.StatusOK && wrapped.bytesWritten > 0 {
			// Enregistrer l'accès (1 fichier par requête réussie)
			go func(ip, ua string, bytes int64) {
				s.clientsDB.RecordAccess(ip, ua, 1, bytes)
			}(clientIP, userAgent, wrapped.bytesWritten)
		}

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
	rateLimiter  *rateLimiter
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Apply rate limiting if configured
	if rw.rateLimiter != nil {
		return rw.rateLimiter.Write(rw.ResponseWriter, b, &rw.bytesWritten)
	}

	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// rateLimiter implements bandwidth limiting
type rateLimiter struct {
	bytesPerSecond int64
	lastTime       time.Time
	bytesSent      int64
	mu             sync.Mutex
}

// newRateLimiter creates a new rate limiter with the specified bytes per second
func newRateLimiter(bytesPerSecond int64) *rateLimiter {
	return &rateLimiter{
		bytesPerSecond: bytesPerSecond,
		lastTime:       time.Now(),
	}
}

// Write writes data with rate limiting
func (rl *rateLimiter) Write(w io.Writer, b []byte, totalWritten *int64) (int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	totalBytes := len(b)
	written := 0

	// Write in chunks to apply rate limiting
	chunkSize := int(rl.bytesPerSecond / 10) // 100ms chunks
	if chunkSize < 1024 {
		chunkSize = 1024 // Minimum 1KB chunks
	}
	if chunkSize > totalBytes {
		chunkSize = totalBytes
	}

	for written < totalBytes {
		// Calculate how many bytes we can send
		now := time.Now()
		elapsed := now.Sub(rl.lastTime)

		// Calculate allowed bytes based on elapsed time
		allowedBytes := int64(elapsed.Seconds() * float64(rl.bytesPerSecond))

		// If we've sent too much, sleep
		if rl.bytesSent >= allowedBytes && elapsed < time.Second {
			sleepTime := time.Duration(float64(rl.bytesSent-allowedBytes) / float64(rl.bytesPerSecond) * float64(time.Second))
			if sleepTime > 0 {
				time.Sleep(sleepTime)
			}
		}

		// Reset counter every second
		if elapsed >= time.Second {
			rl.lastTime = now
			rl.bytesSent = 0
		}

		// Write chunk
		end := written + chunkSize
		if end > totalBytes {
			end = totalBytes
		}

		n, err := w.Write(b[written:end])
		written += n
		rl.bytesSent += int64(n)
		*totalWritten += int64(n)

		if err != nil {
			return written, err
		}
	}

	return written, nil
}
