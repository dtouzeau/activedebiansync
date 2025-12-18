package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SyncEvent represents a synchronization event record
type SyncEvent struct {
	ID             int64     `json:"id"`
	Date           time.Time `json:"date"`
	NumFiles       int64     `json:"num_files"`
	NumSize        int64     `json:"num_size"`
	RepositoryName string    `json:"repository_name"`
	Duration       int64     `json:"duration_ms,omitempty"` // Duration in milliseconds
	FailedFiles    int64     `json:"failed_files,omitempty"`
}

// EventsDB manages the sync events database
type EventsDB struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewEventsDB creates a new EventsDB instance
// dbDir is the directory where the database file will be stored
func NewEventsDB(dbDir string) (*EventsDB, error) {
	dbPath := filepath.Join(dbDir, "events.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open events database: %w", err)
	}

	// Create table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS sync_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		num_files INTEGER NOT NULL DEFAULT 0,
		num_size INTEGER NOT NULL DEFAULT 0,
		repository_name TEXT NOT NULL,
		duration_ms INTEGER DEFAULT 0,
		failed_files INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_sync_events_date ON sync_events(date);
	CREATE INDEX IF NOT EXISTS idx_sync_events_repository ON sync_events(repository_name);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create sync_events table: %w", err)
	}

	eventsDB := &EventsDB{
		db:     db,
		dbPath: dbPath,
	}

	// Run initial cleanup
	go eventsDB.CleanupOldEvents(15)

	return eventsDB, nil
}

// Close closes the database connection
func (e *EventsDB) Close() error {
	if e.db != nil {
		return e.db.Close()
	}
	return nil
}

// RecordSyncEvent records a new synchronization event
func (e *EventsDB) RecordSyncEvent(numFiles, numSize int64, repositoryName string, durationMs, failedFiles int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	query := `
		INSERT INTO sync_events (date, num_files, num_size, repository_name, duration_ms, failed_files)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := e.db.Exec(query, time.Now(), numFiles, numSize, repositoryName, durationMs, failedFiles)
	if err != nil {
		return fmt.Errorf("failed to record sync event: %w", err)
	}

	return nil
}

// GetRecentEvents returns the most recent sync events
func (e *EventsDB) GetRecentEvents(limit int) ([]SyncEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, date, num_files, num_size, repository_name, duration_ms, failed_files
		FROM sync_events
		ORDER BY date DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync events: %w", err)
	}
	defer rows.Close()

	var events []SyncEvent
	for rows.Next() {
		var event SyncEvent
		var durationMs, failedFiles sql.NullInt64
		if err := rows.Scan(&event.ID, &event.Date, &event.NumFiles, &event.NumSize, &event.RepositoryName, &durationMs, &failedFiles); err != nil {
			return nil, fmt.Errorf("failed to scan sync event: %w", err)
		}
		if durationMs.Valid {
			event.Duration = durationMs.Int64
		}
		if failedFiles.Valid {
			event.FailedFiles = failedFiles.Int64
		}
		events = append(events, event)
	}

	return events, nil
}

// GetEventsByRepository returns sync events for a specific repository
func (e *EventsDB) GetEventsByRepository(repositoryName string, limit int) ([]SyncEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, date, num_files, num_size, repository_name, duration_ms, failed_files
		FROM sync_events
		WHERE repository_name = ?
		ORDER BY date DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, repositoryName, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync events: %w", err)
	}
	defer rows.Close()

	var events []SyncEvent
	for rows.Next() {
		var event SyncEvent
		var durationMs, failedFiles sql.NullInt64
		if err := rows.Scan(&event.ID, &event.Date, &event.NumFiles, &event.NumSize, &event.RepositoryName, &durationMs, &failedFiles); err != nil {
			return nil, fmt.Errorf("failed to scan sync event: %w", err)
		}
		if durationMs.Valid {
			event.Duration = durationMs.Int64
		}
		if failedFiles.Valid {
			event.FailedFiles = failedFiles.Int64
		}
		events = append(events, event)
	}

	return events, nil
}

// GetEventsByDateRange returns sync events within a date range
func (e *EventsDB) GetEventsByDateRange(startDate, endDate time.Time, limit int) ([]SyncEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT id, date, num_files, num_size, repository_name, duration_ms, failed_files
		FROM sync_events
		WHERE date >= ? AND date <= ?
		ORDER BY date DESC
		LIMIT ?
	`

	rows, err := e.db.Query(query, startDate, endDate, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync events: %w", err)
	}
	defer rows.Close()

	var events []SyncEvent
	for rows.Next() {
		var event SyncEvent
		var durationMs, failedFiles sql.NullInt64
		if err := rows.Scan(&event.ID, &event.Date, &event.NumFiles, &event.NumSize, &event.RepositoryName, &durationMs, &failedFiles); err != nil {
			return nil, fmt.Errorf("failed to scan sync event: %w", err)
		}
		if durationMs.Valid {
			event.Duration = durationMs.Int64
		}
		if failedFiles.Valid {
			event.FailedFiles = failedFiles.Int64
		}
		events = append(events, event)
	}

	return events, nil
}

// GetStatsByRepository returns aggregated stats for each repository
func (e *EventsDB) GetStatsByRepository() ([]RepositoryStats, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	query := `
		SELECT
			repository_name,
			COUNT(*) as total_syncs,
			SUM(num_files) as total_files,
			SUM(num_size) as total_size,
			AVG(duration_ms) as avg_duration,
			SUM(failed_files) as total_failed,
			MAX(date) as last_sync
		FROM sync_events
		GROUP BY repository_name
		ORDER BY last_sync DESC
	`

	rows, err := e.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query repository stats: %w", err)
	}
	defer rows.Close()

	var stats []RepositoryStats
	for rows.Next() {
		var s RepositoryStats
		var avgDuration sql.NullFloat64
		if err := rows.Scan(&s.RepositoryName, &s.TotalSyncs, &s.TotalFiles, &s.TotalSize, &avgDuration, &s.TotalFailed, &s.LastSync); err != nil {
			return nil, fmt.Errorf("failed to scan repository stats: %w", err)
		}
		if avgDuration.Valid {
			s.AvgDuration = int64(avgDuration.Float64)
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// RepositoryStats represents aggregated statistics for a repository
type RepositoryStats struct {
	RepositoryName string    `json:"repository_name"`
	TotalSyncs     int64     `json:"total_syncs"`
	TotalFiles     int64     `json:"total_files"`
	TotalSize      int64     `json:"total_size"`
	AvgDuration    int64     `json:"avg_duration_ms"`
	TotalFailed    int64     `json:"total_failed"`
	LastSync       time.Time `json:"last_sync"`
}

// CleanupOldEvents removes events older than the specified number of days
func (e *EventsDB) CleanupOldEvents(daysToKeep int) (int64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if daysToKeep <= 0 {
		daysToKeep = 15
	}

	cutoffDate := time.Now().AddDate(0, 0, -daysToKeep)

	query := `DELETE FROM sync_events WHERE date < ?`

	result, err := e.db.Exec(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old events: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// GetTotalEventCount returns the total number of events in the database
func (e *EventsDB) GetTotalEventCount() (int64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var count int64
	err := e.db.QueryRow("SELECT COUNT(*) FROM sync_events").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}

// GetDailySummary returns a summary of sync events grouped by day
func (e *EventsDB) GetDailySummary(days int) ([]DailySummary, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if days <= 0 {
		days = 15
	}

	query := `
		SELECT
			DATE(date) as sync_date,
			COUNT(*) as sync_count,
			SUM(num_files) as total_files,
			SUM(num_size) as total_size,
			SUM(failed_files) as total_failed
		FROM sync_events
		WHERE date >= DATE('now', ?)
		GROUP BY DATE(date)
		ORDER BY sync_date DESC
	`

	rows, err := e.db.Query(query, fmt.Sprintf("-%d days", days))
	if err != nil {
		return nil, fmt.Errorf("failed to query daily summary: %w", err)
	}
	defer rows.Close()

	var summaries []DailySummary
	for rows.Next() {
		var s DailySummary
		if err := rows.Scan(&s.Date, &s.SyncCount, &s.TotalFiles, &s.TotalSize, &s.TotalFailed); err != nil {
			return nil, fmt.Errorf("failed to scan daily summary: %w", err)
		}
		summaries = append(summaries, s)
	}

	return summaries, nil
}

// DailySummary represents a daily summary of sync events
type DailySummary struct {
	Date        string `json:"date"`
	SyncCount   int64  `json:"sync_count"`
	TotalFiles  int64  `json:"total_files"`
	TotalSize   int64  `json:"total_size"`
	TotalFailed int64  `json:"total_failed"`
}

// StartPeriodicCleanup starts a background goroutine that cleans up old events periodically
func (e *EventsDB) StartPeriodicCleanup(interval time.Duration, daysToKeep int) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if deleted, err := e.CleanupOldEvents(daysToKeep); err != nil {
				// Log error silently - caller should handle logging
				_ = deleted
			}
		}
	}()
}
