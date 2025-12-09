package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ClientRecord represents a client access record
type ClientRecord struct {
	ID        int64     `json:"id"`
	Date      time.Time `json:"date"`
	IPAddr    string    `json:"ip_addr"`
	UserAgent string    `json:"user_agent"`
	FilesNum  int64     `json:"files_num"`
	BytesNum  int64     `json:"bytes_num"`
}

// ClientStats represents aggregated statistics for a client
type ClientStats struct {
	IPAddr       string    `json:"ip_addr"`
	UserAgent    string    `json:"user_agent"`
	TotalFiles   int64     `json:"total_files"`
	TotalBytes   int64     `json:"total_bytes"`
	RequestCount int64     `json:"request_count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// DailyClientStats represents daily statistics for a client
type DailyClientStats struct {
	Date       string `json:"date"`
	IPAddr     string `json:"ip_addr"`
	TotalFiles int64  `json:"total_files"`
	TotalBytes int64  `json:"total_bytes"`
	Requests   int64  `json:"requests"`
}

// GlobalClientStats represents overall statistics
type GlobalClientStats struct {
	TotalClients     int64 `json:"total_clients"`
	TotalFiles       int64 `json:"total_files"`
	TotalBytes       int64 `json:"total_bytes"`
	TotalRequests    int64 `json:"total_requests"`
	UniqueUserAgents int64 `json:"unique_user_agents"`
	RecordsCount     int64 `json:"records_count"`
}

// ClientsDB manages the clients statistics database
type ClientsDB struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewClientsDB creates a new clients database
func NewClientsDB(configPath string) (*ClientsDB, error) {
	dbPath := filepath.Join(filepath.Dir(configPath), "clients.db")

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open clients database: %w", err)
	}

	clientsDB := &ClientsDB{
		db:     db,
		dbPath: dbPath,
	}

	if err := clientsDB.initSchema(); err != nil {

		db.Close()
		return nil, err
	}

	return clientsDB, nil
}

// initSchema creates the database schema
func (c *ClientsDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		ip_addr TEXT NOT NULL,
		user_agent TEXT,
		files_num INTEGER NOT NULL DEFAULT 0,
		bytes_num INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_clients_date ON clients(date);
	CREATE INDEX IF NOT EXISTS idx_clients_ip_addr ON clients(ip_addr);
	CREATE INDEX IF NOT EXISTS idx_clients_date_ip ON clients(date, ip_addr);
	`

	_, err := c.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create clients schema: %w", err)
	}

	return nil
}

// RecordAccess records a client access
func (c *ClientsDB) RecordAccess(ipAddr, userAgent string, filesNum, bytesNum int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.db.Exec(`
		INSERT INTO clients (date, ip_addr, user_agent, files_num, bytes_num)
		VALUES (?, ?, ?, ?, ?)
	`, time.Now(), ipAddr, userAgent, filesNum, bytesNum)

	if err != nil {
		return fmt.Errorf("failed to record client access: %w", err)
	}

	return nil
}

// GetRecentRecords returns recent client access records
func (c *ClientsDB) GetRecentRecords(limit int) ([]ClientRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := c.db.Query(`
		SELECT id, date, ip_addr, user_agent, files_num, bytes_num
		FROM clients
		ORDER BY date DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent records: %w", err)
	}
	defer rows.Close()

	var records []ClientRecord
	for rows.Next() {
		var r ClientRecord
		var dateStr string
		if err := rows.Scan(&r.ID, &dateStr, &r.IPAddr, &r.UserAgent, &r.FilesNum, &r.BytesNum); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		r.Date, _ = time.Parse("2006-01-02 15:04:05", dateStr)
		records = append(records, r)
	}

	return records, nil
}

// GetClientStats returns aggregated statistics per client IP
func (c *ClientsDB) GetClientStats(limit int) ([]ClientStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := c.db.Query(`
		SELECT
			ip_addr,
			MAX(user_agent) as user_agent,
			SUM(files_num) as total_files,
			SUM(bytes_num) as total_bytes,
			COUNT(*) as request_count,
			MIN(date) as first_seen,
			MAX(date) as last_seen
		FROM clients
		GROUP BY ip_addr
		ORDER BY total_bytes DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get client stats: %w", err)
	}
	defer rows.Close()

	var stats []ClientStats
	for rows.Next() {
		var s ClientStats
		var firstStr, lastStr string
		if err := rows.Scan(&s.IPAddr, &s.UserAgent, &s.TotalFiles, &s.TotalBytes, &s.RequestCount, &firstStr, &lastStr); err != nil {
			return nil, fmt.Errorf("failed to scan stats: %w", err)
		}
		s.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstStr)
		s.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastStr)
		stats = append(stats, s)
	}

	return stats, nil
}

// GetDailyStats returns daily aggregated statistics
func (c *ClientsDB) GetDailyStats(days int) ([]DailyClientStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if days <= 0 {
		days = 30
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	rows, err := c.db.Query(`
		SELECT
			DATE(date) as day,
			ip_addr,
			SUM(files_num) as total_files,
			SUM(bytes_num) as total_bytes,
			COUNT(*) as requests
		FROM clients
		WHERE date >= ?
		GROUP BY DATE(date), ip_addr
		ORDER BY day DESC, total_bytes DESC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily stats: %w", err)
	}
	defer rows.Close()

	var stats []DailyClientStats
	for rows.Next() {
		var s DailyClientStats
		if err := rows.Scan(&s.Date, &s.IPAddr, &s.TotalFiles, &s.TotalBytes, &s.Requests); err != nil {
			return nil, fmt.Errorf("failed to scan daily stats: %w", err)
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// GetDailySummary returns daily summary statistics (aggregated across all clients)
func (c *ClientsDB) GetDailySummary(days int) ([]map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if days <= 0 {
		days = 30
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	rows, err := c.db.Query(`
		SELECT
			DATE(date) as day,
			COUNT(DISTINCT ip_addr) as unique_clients,
			SUM(files_num) as total_files,
			SUM(bytes_num) as total_bytes,
			COUNT(*) as total_requests
		FROM clients
		WHERE date >= ?
		GROUP BY DATE(date)
		ORDER BY day DESC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily summary: %w", err)
	}
	defer rows.Close()

	var summary []map[string]interface{}
	for rows.Next() {
		var day string
		var uniqueClients, totalFiles, totalBytes, totalRequests int64
		if err := rows.Scan(&day, &uniqueClients, &totalFiles, &totalBytes, &totalRequests); err != nil {
			return nil, fmt.Errorf("failed to scan daily summary: %w", err)
		}
		summary = append(summary, map[string]interface{}{
			"date":           day,
			"unique_clients": uniqueClients,
			"total_files":    totalFiles,
			"total_bytes":    totalBytes,
			"total_requests": totalRequests,
		})
	}

	return summary, nil
}

// GetGlobalStats returns overall statistics
func (c *ClientsDB) GetGlobalStats() (*GlobalClientStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var stats GlobalClientStats

	err := c.db.QueryRow(`
		SELECT
			COUNT(DISTINCT ip_addr),
			COALESCE(SUM(files_num), 0),
			COALESCE(SUM(bytes_num), 0),
			COUNT(*),
			COUNT(DISTINCT user_agent)
		FROM clients
	`).Scan(&stats.TotalClients, &stats.TotalFiles, &stats.TotalBytes, &stats.TotalRequests, &stats.UniqueUserAgents)
	if err != nil {
		return nil, fmt.Errorf("failed to get global stats: %w", err)
	}

	err = c.db.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&stats.RecordsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get records count: %w", err)
	}

	return &stats, nil
}

// GetTopClients returns top clients by bandwidth usage
func (c *ClientsDB) GetTopClients(limit int, days int) ([]ClientStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}
	if days <= 0 {
		days = 30
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	rows, err := c.db.Query(`
		SELECT
			ip_addr,
			MAX(user_agent) as user_agent,
			SUM(files_num) as total_files,
			SUM(bytes_num) as total_bytes,
			COUNT(*) as request_count,
			MIN(date) as first_seen,
			MAX(date) as last_seen
		FROM clients
		WHERE date >= ?
		GROUP BY ip_addr
		ORDER BY total_bytes DESC
		LIMIT ?
	`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get top clients: %w", err)
	}
	defer rows.Close()

	var stats []ClientStats
	for rows.Next() {
		var s ClientStats
		var firstStr, lastStr string
		if err := rows.Scan(&s.IPAddr, &s.UserAgent, &s.TotalFiles, &s.TotalBytes, &s.RequestCount, &firstStr, &lastStr); err != nil {
			return nil, fmt.Errorf("failed to scan top client: %w", err)
		}
		s.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstStr)
		s.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastStr)
		stats = append(stats, s)
	}

	return stats, nil
}

// GetClientHistory returns access history for a specific client IP
func (c *ClientsDB) GetClientHistory(ipAddr string, limit int) ([]ClientRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := c.db.Query(`
		SELECT id, date, ip_addr, user_agent, files_num, bytes_num
		FROM clients
		WHERE ip_addr = ?
		ORDER BY date DESC
		LIMIT ?
	`, ipAddr, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get client history: %w", err)
	}
	defer rows.Close()

	var records []ClientRecord
	for rows.Next() {
		var r ClientRecord
		var dateStr string
		if err := rows.Scan(&r.ID, &dateStr, &r.IPAddr, &r.UserAgent, &r.FilesNum, &r.BytesNum); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		r.Date, _ = time.Parse("2006-01-02 15:04:05", dateStr)
		records = append(records, r)
	}

	return records, nil
}

// CleanupOldRecords removes records older than the specified number of days
func (c *ClientsDB) CleanupOldRecords(days int) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if days <= 0 {
		days = 30 // Default: 1 month
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	result, err := c.db.Exec(`DELETE FROM clients WHERE date < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old records: %w", err)
	}

	deleted, _ := result.RowsAffected()
	return deleted, nil
}

// Close closes the database connection
func (c *ClientsDB) Close() error {
	return c.db.Close()
}
