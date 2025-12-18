package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ClusterNode represents a peer node in the cluster
type ClusterNode struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Enabled     bool      `json:"enabled"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"` // "online", "offline", "syncing", "error"
	LastError   string    `json:"last_error,omitempty"`
	TotalPushes int64     `json:"total_pushes"`
	TotalPulls  int64     `json:"total_pulls"`
	BytesPushed int64     `json:"bytes_pushed"`
	BytesPulled int64     `json:"bytes_pulled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ReplicationEvent represents a single replication operation
type ReplicationEvent struct {
	ID               int64     `json:"id"`
	NodeID           int64     `json:"node_id"`
	NodeName         string    `json:"node_name"`
	Direction        string    `json:"direction"` // "push" or "pull"
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	DurationMs       int64     `json:"duration_ms"`
	BytesTransferred int64     `json:"bytes_transferred"`
	FilesTransferred int64     `json:"files_transferred"`
	FilesSkipped     int64     `json:"files_skipped"`
	Status           string    `json:"status"` // "running", "success", "failed", "partial"
	ErrorMessage     string    `json:"error_message,omitempty"`
	Compression      string    `json:"compression"`
	Bandwidth        float64   `json:"bandwidth"` // Calculated bandwidth in bytes/second
}

// BandwidthString returns a human-readable bandwidth string
func (e *ReplicationEvent) BandwidthString() string {
	if e.Bandwidth <= 0 || e.DurationMs <= 0 {
		return "-"
	}
	if e.Bandwidth >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB/s", e.Bandwidth/(1024*1024*1024))
	}
	if e.Bandwidth >= 1024*1024 {
		return fmt.Sprintf("%.2f MB/s", e.Bandwidth/(1024*1024))
	}
	if e.Bandwidth >= 1024 {
		return fmt.Sprintf("%.2f KB/s", e.Bandwidth/1024)
	}
	return fmt.Sprintf("%.0f B/s", e.Bandwidth)
}

// ClusterStats represents aggregated cluster statistics
type ClusterStats struct {
	TotalNodes          int64     `json:"total_nodes"`
	OnlineNodes         int64     `json:"online_nodes"`
	TotalReplications   int64     `json:"total_replications"`
	TotalBytesSynced    int64     `json:"total_bytes_synced"`
	TotalFilesSynced    int64     `json:"total_files_synced"`
	LastReplication     time.Time `json:"last_replication"`
	ActiveReplications  int64     `json:"active_replications"`
	AverageBandwidth    float64   `json:"average_bandwidth"`     // Average bandwidth in bytes/second
	AverageBandwidthStr string    `json:"average_bandwidth_str"` // Human-readable average bandwidth
}

// ClusterDB manages cluster replication statistics
type ClusterDB struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewClusterDB creates a new ClusterDB instance
// dbDir is the directory where the database file will be stored
func NewClusterDB(dbDir string) (*ClusterDB, error) {
	dbPath := filepath.Join(dbDir, "cluster.db")

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open cluster database: %w", err)
	}

	clusterDB := &ClusterDB{
		db:     db,
		dbPath: dbPath,
	}

	if err := clusterDB.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	return clusterDB, nil
}

// initSchema creates the database schema
func (c *ClusterDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS cluster_nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		address TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 9191,
		enabled INTEGER NOT NULL DEFAULT 1,
		last_seen DATETIME,
		status TEXT NOT NULL DEFAULT 'unknown',
		last_error TEXT,
		total_pushes INTEGER DEFAULT 0,
		total_pulls INTEGER DEFAULT 0,
		bytes_pushed INTEGER DEFAULT 0,
		bytes_pulled INTEGER DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS replication_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER,
		node_name TEXT NOT NULL,
		direction TEXT NOT NULL CHECK(direction IN ('push', 'pull')),
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration_ms INTEGER,
		bytes_transferred INTEGER DEFAULT 0,
		files_transferred INTEGER DEFAULT 0,
		files_skipped INTEGER DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'running',
		error_message TEXT,
		compression TEXT,
		FOREIGN KEY (node_id) REFERENCES cluster_nodes(id)
	);

	CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);
	CREATE INDEX IF NOT EXISTS idx_cluster_nodes_name ON cluster_nodes(name);
	CREATE INDEX IF NOT EXISTS idx_replication_events_node ON replication_events(node_id);
	CREATE INDEX IF NOT EXISTS idx_replication_events_start ON replication_events(start_time);
	CREATE INDEX IF NOT EXISTS idx_replication_events_status ON replication_events(status);
	`

	_, err := c.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create cluster schema: %w", err)
	}

	return nil
}

// UpsertNode creates or updates a cluster node
func (c *ClusterDB) UpsertNode(node ClusterNode) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.db.Exec(`
		INSERT INTO cluster_nodes (name, address, port, enabled, status, last_seen, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			address = excluded.address,
			port = excluded.port,
			enabled = excluded.enabled,
			status = excluded.status,
			last_seen = excluded.last_seen,
			updated_at = CURRENT_TIMESTAMP
	`, node.Name, node.Address, node.Port, node.Enabled, node.Status, node.LastSeen)

	if err != nil {
		return fmt.Errorf("failed to upsert node: %w", err)
	}

	return nil
}

// GetAllNodes returns all cluster nodes
func (c *ClusterDB) GetAllNodes() ([]ClusterNode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rows, err := c.db.Query(`
		SELECT id, name, address, port, enabled, last_seen, status, last_error,
		       total_pushes, total_pulls, bytes_pushed, bytes_pulled, created_at, updated_at
		FROM cluster_nodes
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}
	defer rows.Close()

	var nodes []ClusterNode
	for rows.Next() {
		var n ClusterNode
		var lastSeen, createdAt, updatedAt sql.NullString
		var lastError sql.NullString

		if err := rows.Scan(&n.ID, &n.Name, &n.Address, &n.Port, &n.Enabled,
			&lastSeen, &n.Status, &lastError,
			&n.TotalPushes, &n.TotalPulls, &n.BytesPushed, &n.BytesPulled,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan node: %w", err)
		}

		if lastSeen.Valid {
			n.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen.String)
		}
		if createdAt.Valid {
			n.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt.String)
		}
		if updatedAt.Valid {
			n.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt.String)
		}
		if lastError.Valid {
			n.LastError = lastError.String
		}

		nodes = append(nodes, n)
	}

	return nodes, nil
}

// GetNodeByName returns a node by name
func (c *ClusterDB) GetNodeByName(name string) (*ClusterNode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var n ClusterNode
	var lastSeen, createdAt, updatedAt sql.NullString
	var lastError sql.NullString

	err := c.db.QueryRow(`
		SELECT id, name, address, port, enabled, last_seen, status, last_error,
		       total_pushes, total_pulls, bytes_pushed, bytes_pulled, created_at, updated_at
		FROM cluster_nodes
		WHERE name = ?
	`, name).Scan(&n.ID, &n.Name, &n.Address, &n.Port, &n.Enabled,
		&lastSeen, &n.Status, &lastError,
		&n.TotalPushes, &n.TotalPulls, &n.BytesPushed, &n.BytesPulled,
		&createdAt, &updatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get node: %w", err)
	}

	if lastSeen.Valid {
		n.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen.String)
	}
	if createdAt.Valid {
		n.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt.String)
	}
	if updatedAt.Valid {
		n.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt.String)
	}
	if lastError.Valid {
		n.LastError = lastError.String
	}

	return &n, nil
}

// UpdateNodeStatus updates the status of a node
func (c *ClusterDB) UpdateNodeStatus(name, status, lastError string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.db.Exec(`
		UPDATE cluster_nodes
		SET status = ?, last_error = ?, last_seen = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE name = ?
	`, status, lastError, name)

	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}

	return nil
}

// DeleteNode removes a node from the cluster
func (c *ClusterDB) DeleteNode(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.db.Exec(`DELETE FROM cluster_nodes WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("failed to delete node: %w", err)
	}

	return nil
}

// RecordReplicationStart records the start of a replication event
func (c *ClusterDB) RecordReplicationStart(event ReplicationEvent) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Format time in SQLite-compatible format
	startTimeStr := event.StartTime.Format("2006-01-02 15:04:05")

	result, err := c.db.Exec(`
		INSERT INTO replication_events (node_id, node_name, direction, start_time, status, compression)
		VALUES (?, ?, ?, ?, 'running', ?)
	`, event.NodeID, event.NodeName, event.Direction, startTimeStr, event.Compression)

	if err != nil {
		return 0, fmt.Errorf("failed to record replication start: %w", err)
	}

	return result.LastInsertId()
}

// RecordReplicationEnd records the completion of a replication event
func (c *ClusterDB) RecordReplicationEnd(eventID int64, event ReplicationEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Format time in SQLite-compatible format
	endTimeStr := event.EndTime.Format("2006-01-02 15:04:05")

	_, err := c.db.Exec(`
		UPDATE replication_events
		SET end_time = ?, duration_ms = ?, bytes_transferred = ?, files_transferred = ?,
		    files_skipped = ?, status = ?, error_message = ?
		WHERE id = ?
	`, endTimeStr, event.DurationMs, event.BytesTransferred, event.FilesTransferred,
		event.FilesSkipped, event.Status, event.ErrorMessage, eventID)

	if err != nil {
		return fmt.Errorf("failed to record replication end: %w", err)
	}

	// Update node statistics
	// Treat 'success' and 'partial' as online (partial means data was transferred but connection dropped at end)
	if event.Direction == "push" {
		_, err = c.db.Exec(`
			UPDATE cluster_nodes
			SET total_pushes = total_pushes + 1,
			    bytes_pushed = bytes_pushed + ?,
			    last_seen = CURRENT_TIMESTAMP,
			    status = CASE WHEN ? IN ('success', 'partial') THEN 'online' ELSE 'error' END,
			    last_error = CASE WHEN ? = 'success' THEN NULL ELSE ? END
			WHERE name = ?
		`, event.BytesTransferred, event.Status, event.Status, event.ErrorMessage, event.NodeName)
	} else {
		_, err = c.db.Exec(`
			UPDATE cluster_nodes
			SET total_pulls = total_pulls + 1,
			    bytes_pulled = bytes_pulled + ?,
			    last_seen = CURRENT_TIMESTAMP,
			    status = CASE WHEN ? IN ('success', 'partial') THEN 'online' ELSE 'error' END,
			    last_error = CASE WHEN ? = 'success' THEN NULL ELSE ? END
			WHERE name = ?
		`, event.BytesTransferred, event.Status, event.Status, event.ErrorMessage, event.NodeName)
	}

	return err
}

// GetRecentEvents returns recent replication events
func (c *ClusterDB) GetRecentEvents(limit int) ([]ReplicationEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	rows, err := c.db.Query(`
		SELECT id, node_id, node_name, direction, start_time, end_time, duration_ms,
		       bytes_transferred, files_transferred, files_skipped, status, error_message, compression
		FROM replication_events
		ORDER BY start_time DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent events: %w", err)
	}
	defer rows.Close()

	var events []ReplicationEvent
	for rows.Next() {
		var e ReplicationEvent
		var nodeID, durationMs, bytesTransferred, filesTransferred, filesSkipped sql.NullInt64
		var startTime, endTime sql.NullString
		var errorMsg, compression sql.NullString

		if err := rows.Scan(&e.ID, &nodeID, &e.NodeName, &e.Direction,
			&startTime, &endTime, &durationMs,
			&bytesTransferred, &filesTransferred, &filesSkipped,
			&e.Status, &errorMsg, &compression); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if nodeID.Valid {
			e.NodeID = nodeID.Int64
		}
		if durationMs.Valid {
			e.DurationMs = durationMs.Int64
		}
		if bytesTransferred.Valid {
			e.BytesTransferred = bytesTransferred.Int64
		}
		if filesTransferred.Valid {
			e.FilesTransferred = filesTransferred.Int64
		}
		if filesSkipped.Valid {
			e.FilesSkipped = filesSkipped.Int64
		}
		if startTime.Valid {
			e.StartTime = parseFlexibleTime(startTime.String)
		}
		if endTime.Valid {
			e.EndTime = parseFlexibleTime(endTime.String)
		}
		if errorMsg.Valid {
			e.ErrorMessage = errorMsg.String
		}
		if compression.Valid {
			e.Compression = compression.String
		}

		// Calculate bandwidth (bytes per second)
		if e.DurationMs > 0 && e.BytesTransferred > 0 {
			e.Bandwidth = float64(e.BytesTransferred) / (float64(e.DurationMs) / 1000.0)
		}

		events = append(events, e)
	}

	return events, nil
}

// parseFlexibleTime parses time strings in various formats
func parseFlexibleTime(s string) time.Time {
	// Try multiple formats
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05.999999999-07:00",
		time.RFC3339,
		time.RFC3339Nano,
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetClusterStats returns aggregated cluster statistics
func (c *ClusterDB) GetClusterStats() (*ClusterStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &ClusterStats{}

	// Get node counts
	err := c.db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes`).Scan(&stats.TotalNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get total nodes: %w", err)
	}

	err = c.db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes WHERE status = 'online'`).Scan(&stats.OnlineNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get online nodes: %w", err)
	}

	// Get replication stats
	err = c.db.QueryRow(`SELECT COUNT(*) FROM replication_events`).Scan(&stats.TotalReplications)
	if err != nil {
		return nil, fmt.Errorf("failed to get total replications: %w", err)
	}

	// Include both 'success' and 'partial' since partial replications still transferred data
	err = c.db.QueryRow(`SELECT COALESCE(SUM(bytes_transferred), 0) FROM replication_events WHERE status IN ('success', 'partial')`).Scan(&stats.TotalBytesSynced)
	if err != nil {
		return nil, fmt.Errorf("failed to get total bytes synced: %w", err)
	}

	err = c.db.QueryRow(`SELECT COALESCE(SUM(files_transferred), 0) FROM replication_events WHERE status IN ('success', 'partial')`).Scan(&stats.TotalFilesSynced)
	if err != nil {
		return nil, fmt.Errorf("failed to get total files synced: %w", err)
	}

	// Get last replication time (any completed replication)
	var lastRepStr sql.NullString
	err = c.db.QueryRow(`SELECT MAX(end_time) FROM replication_events WHERE status IN ('success', 'partial')`).Scan(&lastRepStr)
	if err == nil && lastRepStr.Valid {
		stats.LastReplication, _ = time.Parse("2006-01-02 15:04:05", lastRepStr.String)
	}

	// Get active replications
	err = c.db.QueryRow(`SELECT COUNT(*) FROM replication_events WHERE status = 'running'`).Scan(&stats.ActiveReplications)
	if err != nil {
		return nil, fmt.Errorf("failed to get active replications: %w", err)
	}

	// Calculate average bandwidth from recent completed replications
	var totalBytes, totalDurationMs sql.NullInt64
	err = c.db.QueryRow(`
		SELECT COALESCE(SUM(bytes_transferred), 0), COALESCE(SUM(duration_ms), 0)
		FROM replication_events
		WHERE status IN ('success', 'partial') AND duration_ms > 0
	`).Scan(&totalBytes, &totalDurationMs)
	if err == nil && totalDurationMs.Valid && totalDurationMs.Int64 > 0 && totalBytes.Valid {
		// Calculate bytes per second
		stats.AverageBandwidth = float64(totalBytes.Int64) / (float64(totalDurationMs.Int64) / 1000.0)
		// Format as human readable
		if stats.AverageBandwidth >= 1024*1024*1024 {
			stats.AverageBandwidthStr = fmt.Sprintf("%.2f GB/s", stats.AverageBandwidth/(1024*1024*1024))
		} else if stats.AverageBandwidth >= 1024*1024 {
			stats.AverageBandwidthStr = fmt.Sprintf("%.2f MB/s", stats.AverageBandwidth/(1024*1024))
		} else if stats.AverageBandwidth >= 1024 {
			stats.AverageBandwidthStr = fmt.Sprintf("%.2f KB/s", stats.AverageBandwidth/1024)
		} else {
			stats.AverageBandwidthStr = fmt.Sprintf("%.0f B/s", stats.AverageBandwidth)
		}
	}

	return stats, nil
}

// GetNodeEvents returns replication events for a specific node
func (c *ClusterDB) GetNodeEvents(nodeName string, limit int) ([]ReplicationEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	rows, err := c.db.Query(`
		SELECT id, node_id, node_name, direction, start_time, end_time, duration_ms,
		       bytes_transferred, files_transferred, files_skipped, status, error_message, compression
		FROM replication_events
		WHERE node_name = ?
		ORDER BY start_time DESC
		LIMIT ?
	`, nodeName, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get node events: %w", err)
	}
	defer rows.Close()

	var events []ReplicationEvent
	for rows.Next() {
		var e ReplicationEvent
		var nodeID, durationMs, bytesTransferred, filesTransferred, filesSkipped sql.NullInt64
		var startTime, endTime sql.NullString
		var errorMsg, compression sql.NullString

		if err := rows.Scan(&e.ID, &nodeID, &e.NodeName, &e.Direction,
			&startTime, &endTime, &durationMs,
			&bytesTransferred, &filesTransferred, &filesSkipped,
			&e.Status, &errorMsg, &compression); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if nodeID.Valid {
			e.NodeID = nodeID.Int64
		}
		if durationMs.Valid {
			e.DurationMs = durationMs.Int64
		}
		if bytesTransferred.Valid {
			e.BytesTransferred = bytesTransferred.Int64
		}
		if filesTransferred.Valid {
			e.FilesTransferred = filesTransferred.Int64
		}
		if filesSkipped.Valid {
			e.FilesSkipped = filesSkipped.Int64
		}
		if startTime.Valid {
			e.StartTime = parseFlexibleTime(startTime.String)
		}
		if endTime.Valid {
			e.EndTime = parseFlexibleTime(endTime.String)
		}
		if errorMsg.Valid {
			e.ErrorMessage = errorMsg.String
		}
		if compression.Valid {
			e.Compression = compression.String
		}

		events = append(events, e)
	}

	return events, nil
}

// CleanupOldEvents removes events older than the specified number of days
func (c *ClusterDB) CleanupOldEvents(days int) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if days <= 0 {
		days = 30 // Default: 30 days
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	result, err := c.db.Exec(`DELETE FROM replication_events WHERE start_time < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old events: %w", err)
	}

	deleted, _ := result.RowsAffected()
	return deleted, nil
}

// Close closes the database connection
func (c *ClusterDB) Close() error {
	return c.db.Close()
}
