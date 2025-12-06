package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// PackageUpdate représente une mise à jour de package téléchargée
type PackageUpdate struct {
	ID                 int64     `json:"id"`
	DownloadedDate     time.Time `json:"downloaded_date"`
	PackageName        string    `json:"package_name"`
	PackageVersion     string    `json:"package_version"`
	PackageDescription string    `json:"package_description"`
	Release            string    `json:"release"`
	Component          string    `json:"component"`
	Architecture       string    `json:"architecture"`
	FileSize           int64     `json:"file_size"`
	Filename           string    `json:"filename"`
}

// UpdatesDB gère la base de données des mises à jour de packages
type UpdatesDB struct {
	db               *sql.DB
	dbPath           string
	mu               sync.RWMutex
	isFirstSync      bool
	firstSyncChecked bool
}

// NewUpdatesDB crée une nouvelle instance de UpdatesDB
// configPath est le chemin vers le fichier de configuration
func NewUpdatesDB(configPath string) (*UpdatesDB, error) {
	dir := filepath.Dir(configPath)
	dbPath := filepath.Join(dir, "package_updates.db")

	// Vérifier si c'est la première synchronisation (DB n'existe pas)
	isFirstSync := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isFirstSync = true
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Créer la table si elle n'existe pas
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS package_updates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		downloaded_date DATETIME NOT NULL,
		package_name TEXT NOT NULL,
		package_version TEXT NOT NULL,
		package_description TEXT,
		release TEXT NOT NULL,
		component TEXT NOT NULL,
		architecture TEXT NOT NULL,
		file_size INTEGER,
		filename TEXT,
		UNIQUE(package_name, package_version, release, component, architecture)
	);

	CREATE INDEX IF NOT EXISTS idx_downloaded_date ON package_updates(downloaded_date);
	CREATE INDEX IF NOT EXISTS idx_package_name ON package_updates(package_name);
	CREATE INDEX IF NOT EXISTS idx_release ON package_updates(release);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &UpdatesDB{
		db:               db,
		dbPath:           dbPath,
		isFirstSync:      isFirstSync,
		firstSyncChecked: false,
	}, nil
}

// IsFirstSync retourne true si c'est la première synchronisation
func (u *UpdatesDB) IsFirstSync() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.isFirstSync
}

// MarkFirstSyncComplete marque la première synchronisation comme terminée
func (u *UpdatesDB) MarkFirstSyncComplete() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.isFirstSync = false
	u.firstSyncChecked = true
}

// SetFirstSyncStatus définit manuellement le statut de première sync
func (u *UpdatesDB) SetFirstSyncStatus(isFirst bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.isFirstSync = isFirst
	u.firstSyncChecked = true
}

// RecordUpdate enregistre une nouvelle mise à jour de package
func (u *UpdatesDB) RecordUpdate(update *PackageUpdate) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Ne pas enregistrer si c'est la première synchronisation
	if u.isFirstSync {
		return nil
	}

	insertSQL := `
	INSERT OR REPLACE INTO package_updates
		(downloaded_date, package_name, package_version, package_description,
		 release, component, architecture, file_size, filename)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := u.db.Exec(insertSQL,
		update.DownloadedDate,
		update.PackageName,
		update.PackageVersion,
		update.PackageDescription,
		update.Release,
		update.Component,
		update.Architecture,
		update.FileSize,
		update.Filename,
	)

	if err != nil {
		return fmt.Errorf("failed to record update: %w", err)
	}

	return nil
}

// RecordUpdates enregistre plusieurs mises à jour en une seule transaction
func (u *UpdatesDB) RecordUpdates(updates []*PackageUpdate) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Ne pas enregistrer si c'est la première synchronisation
	if u.isFirstSync {
		return nil
	}

	if len(updates) == 0 {
		return nil
	}

	tx, err := u.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO package_updates
			(downloaded_date, package_name, package_version, package_description,
			 release, component, architecture, file_size, filename)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, update := range updates {
		_, err := stmt.Exec(
			update.DownloadedDate,
			update.PackageName,
			update.PackageVersion,
			update.PackageDescription,
			update.Release,
			update.Component,
			update.Architecture,
			update.FileSize,
			update.Filename,
		)
		if err != nil {
			return fmt.Errorf("failed to insert update for %s: %w", update.PackageName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// QueryOptions contient les options de requête pour les mises à jour
type QueryOptions struct {
	PackageName  string     // Filtrer par nom de package (LIKE)
	Release      string     // Filtrer par release
	Component    string     // Filtrer par composant
	Architecture string     // Filtrer par architecture
	Since        *time.Time // Mises à jour depuis cette date
	Until        *time.Time // Mises à jour jusqu'à cette date
	Limit        int        // Nombre maximum de résultats
	Offset       int        // Offset pour pagination
}

// GetUpdates récupère les mises à jour selon les options
func (u *UpdatesDB) GetUpdates(opts QueryOptions) ([]*PackageUpdate, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	query := `SELECT id, downloaded_date, package_name, package_version,
	          package_description, release, component, architecture, file_size, filename
	          FROM package_updates WHERE 1=1`
	var args []interface{}

	if opts.PackageName != "" {
		query += " AND package_name LIKE ?"
		args = append(args, "%"+opts.PackageName+"%")
	}

	if opts.Release != "" {
		query += " AND release = ?"
		args = append(args, opts.Release)
	}

	if opts.Component != "" {
		query += " AND component = ?"
		args = append(args, opts.Component)
	}

	if opts.Architecture != "" {
		query += " AND architecture = ?"
		args = append(args, opts.Architecture)
	}

	if opts.Since != nil {
		query += " AND downloaded_date >= ?"
		args = append(args, *opts.Since)
	}

	if opts.Until != nil {
		query += " AND downloaded_date <= ?"
		args = append(args, *opts.Until)
	}

	query += " ORDER BY downloaded_date DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	if opts.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, opts.Offset)
	}

	rows, err := u.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query updates: %w", err)
	}
	defer rows.Close()

	var updates []*PackageUpdate
	for rows.Next() {
		var update PackageUpdate
		var desc sql.NullString
		var filename sql.NullString

		err := rows.Scan(
			&update.ID,
			&update.DownloadedDate,
			&update.PackageName,
			&update.PackageVersion,
			&desc,
			&update.Release,
			&update.Component,
			&update.Architecture,
			&update.FileSize,
			&filename,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if desc.Valid {
			update.PackageDescription = desc.String
		}
		if filename.Valid {
			update.Filename = filename.String
		}

		updates = append(updates, &update)
	}

	return updates, nil
}

// GetRecentUpdates récupère les N dernières mises à jour
func (u *UpdatesDB) GetRecentUpdates(limit int) ([]*PackageUpdate, error) {
	return u.GetUpdates(QueryOptions{Limit: limit})
}

// GetUpdatesSince récupère les mises à jour depuis une date
func (u *UpdatesDB) GetUpdatesSince(since time.Time) ([]*PackageUpdate, error) {
	return u.GetUpdates(QueryOptions{Since: &since})
}

// GetUpdatesToday récupère les mises à jour d'aujourd'hui
func (u *UpdatesDB) GetUpdatesToday() ([]*PackageUpdate, error) {
	today := time.Now().Truncate(24 * time.Hour)
	return u.GetUpdates(QueryOptions{Since: &today})
}

// CountUpdates compte le nombre total de mises à jour enregistrées
func (u *UpdatesDB) CountUpdates() (int64, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var count int64
	err := u.db.QueryRow("SELECT COUNT(*) FROM package_updates").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count updates: %w", err)
	}

	return count, nil
}

// CountUpdatesSince compte les mises à jour depuis une date
func (u *UpdatesDB) CountUpdatesSince(since time.Time) (int64, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var count int64
	err := u.db.QueryRow("SELECT COUNT(*) FROM package_updates WHERE downloaded_date >= ?", since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count updates: %w", err)
	}

	return count, nil
}

// GetStats retourne des statistiques sur les mises à jour
func (u *UpdatesDB) GetStats() (*UpdateStats, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	stats := &UpdateStats{}

	// Total des mises à jour
	err := u.db.QueryRow("SELECT COUNT(*) FROM package_updates").Scan(&stats.TotalUpdates)
	if err != nil {
		return nil, fmt.Errorf("failed to get total count: %w", err)
	}

	// Mises à jour aujourd'hui
	today := time.Now().Truncate(24 * time.Hour)
	err = u.db.QueryRow("SELECT COUNT(*) FROM package_updates WHERE downloaded_date >= ?", today).Scan(&stats.TodayUpdates)
	if err != nil {
		return nil, fmt.Errorf("failed to get today count: %w", err)
	}

	// Mises à jour cette semaine
	weekAgo := time.Now().AddDate(0, 0, -7)
	err = u.db.QueryRow("SELECT COUNT(*) FROM package_updates WHERE downloaded_date >= ?", weekAgo).Scan(&stats.WeekUpdates)
	if err != nil {
		return nil, fmt.Errorf("failed to get week count: %w", err)
	}

	// Mises à jour ce mois
	monthAgo := time.Now().AddDate(0, -1, 0)
	err = u.db.QueryRow("SELECT COUNT(*) FROM package_updates WHERE downloaded_date >= ?", monthAgo).Scan(&stats.MonthUpdates)
	if err != nil {
		return nil, fmt.Errorf("failed to get month count: %w", err)
	}

	// Dernière mise à jour
	var lastUpdate sql.NullTime
	err = u.db.QueryRow("SELECT MAX(downloaded_date) FROM package_updates").Scan(&lastUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to get last update: %w", err)
	}
	if lastUpdate.Valid {
		stats.LastUpdate = &lastUpdate.Time
	}

	// Taille totale des packages
	var totalSize sql.NullInt64
	err = u.db.QueryRow("SELECT SUM(file_size) FROM package_updates").Scan(&totalSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get total size: %w", err)
	}
	if totalSize.Valid {
		stats.TotalSize = totalSize.Int64
	}

	return stats, nil
}

// UpdateStats contient les statistiques des mises à jour
type UpdateStats struct {
	TotalUpdates int64      `json:"total_updates"`
	TodayUpdates int64      `json:"today_updates"`
	WeekUpdates  int64      `json:"week_updates"`
	MonthUpdates int64      `json:"month_updates"`
	LastUpdate   *time.Time `json:"last_update,omitempty"`
	TotalSize    int64      `json:"total_size_bytes"`
}

// DeleteOldUpdates supprime les mises à jour plus anciennes qu'une certaine date
func (u *UpdatesDB) DeleteOldUpdates(before time.Time) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	result, err := u.db.Exec("DELETE FROM package_updates WHERE downloaded_date < ?", before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old updates: %w", err)
	}

	return result.RowsAffected()
}

// Close ferme la connexion à la base de données
func (u *UpdatesDB) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.db != nil {
		return u.db.Close()
	}
	return nil
}

// GetDBPath retourne le chemin de la base de données
func (u *UpdatesDB) GetDBPath() string {
	return u.dbPath
}
