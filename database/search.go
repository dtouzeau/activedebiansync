package database

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ulikunitz/xz"
)

// PackageSearchResult représente un résultat de recherche
type PackageSearchResult struct {
	PackageName  string `json:"package_name"`
	Version      string `json:"version,omitempty"`
	Description  string `json:"description,omitempty"`
	Section      string `json:"section,omitempty"`
	Release      string `json:"release"`
	Component    string `json:"component"`
	Architecture string `json:"architecture"`
	Filename     string `json:"filename,omitempty"`
	MatchType    string `json:"match_type"`             // "name", "description", "file"
	MatchedFile  string `json:"matched_file,omitempty"` // Le fichier qui a matché (pour recherche par fichier)
}

// FileEntry représente une entrée fichier -> package
type FileEntry struct {
	FilePath     string
	PackageName  string
	Release      string
	Component    string
	Architecture string
}

// PackageSearchDB gère la base de données de recherche de packages
type PackageSearchDB struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewPackageSearchDB crée une nouvelle instance de PackageSearchDB
// dbDir is the directory where the database file will be stored
func NewPackageSearchDB(dbDir string) (*PackageSearchDB, error) {
	dbPath := filepath.Join(dbDir, "package_search.db")

	db, err := sql.Open("sqlite3", dbPath+"?cache=shared&mode=rwc")
	if err != nil {
		return nil, fmt.Errorf("failed to open search database: %w", err)
	}

	// Optimisations SQLite pour les performances
	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA cache_size=10000;
		PRAGMA temp_store=MEMORY;
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	// Créer les tables
	createTablesSQL := `
	-- Table des packages avec leurs métadonnées
	CREATE TABLE IF NOT EXISTS packages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		package_name TEXT NOT NULL,
		version TEXT,
		description TEXT,
		section TEXT,
		release TEXT NOT NULL,
		component TEXT NOT NULL,
		architecture TEXT NOT NULL,
		filename TEXT,
		indexed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(package_name, version, release, component, architecture)
	);

	-- Table des fichiers contenus dans les packages
	CREATE TABLE IF NOT EXISTS package_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT NOT NULL,
		package_name TEXT NOT NULL,
		release TEXT NOT NULL,
		component TEXT NOT NULL,
		architecture TEXT NOT NULL,
		UNIQUE(file_path, package_name, release, architecture)
	);

	-- Index pour les recherches rapides
	CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(package_name);
	CREATE INDEX IF NOT EXISTS idx_packages_description ON packages(description);
	CREATE INDEX IF NOT EXISTS idx_packages_release ON packages(release);
	CREATE INDEX IF NOT EXISTS idx_files_path ON package_files(file_path);
	CREATE INDEX IF NOT EXISTS idx_files_package ON package_files(package_name);

	-- Table pour suivre l'état de l'indexation
	CREATE TABLE IF NOT EXISTS index_status (
		id INTEGER PRIMARY KEY,
		release TEXT NOT NULL,
		component TEXT NOT NULL,
		architecture TEXT NOT NULL,
		last_indexed DATETIME,
		packages_count INTEGER DEFAULT 0,
		files_count INTEGER DEFAULT 0,
		UNIQUE(release, component, architecture)
	);
	`

	if _, err := db.Exec(createTablesSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &PackageSearchDB{
		db:     db,
		dbPath: dbPath,
	}, nil
}

// IndexPackagesFile indexe un fichier Packages (gz ou xz)
func (ps *PackageSearchDB) IndexPackagesFile(packagesPath, release, component, arch string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	file, err := os.Open(packagesPath)
	if err != nil {
		return fmt.Errorf("failed to open Packages file: %w", err)
	}
	defer file.Close()

	var reader *bufio.Scanner

	if strings.HasSuffix(packagesPath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = bufio.NewScanner(gzReader)
	} else if strings.HasSuffix(packagesPath, ".xz") {
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = bufio.NewScanner(xzReader)
	} else {
		reader = bufio.NewScanner(file)
	}

	// Buffer plus grand pour les longues lignes
	buf := make([]byte, 0, 64*1024)
	reader.Buffer(buf, 1024*1024)

	// Commencer une transaction
	tx, err := ps.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Supprimer les anciennes entrées pour cette release/component/arch
	_, err = tx.Exec("DELETE FROM packages WHERE release = ? AND component = ? AND architecture = ?",
		release, component, arch)
	if err != nil {
		return fmt.Errorf("failed to delete old packages: %w", err)
	}

	// Préparer le statement d'insertion
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO packages
		(package_name, version, description, section, release, component, architecture, filename, indexed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	var currentPkg struct {
		Name        string
		Version     string
		Description string
		Section     string
		Filename    string
	}
	packagesCount := 0
	now := time.Now()

	for reader.Scan() {
		line := reader.Text()

		if line == "" {
			// Fin d'une entrée de package
			if currentPkg.Name != "" {
				_, err := stmt.Exec(
					currentPkg.Name,
					currentPkg.Version,
					currentPkg.Description,
					currentPkg.Section,
					release,
					component,
					arch,
					currentPkg.Filename,
					now,
				)
				if err != nil {
					return fmt.Errorf("failed to insert package %s: %w", currentPkg.Name, err)
				}
				packagesCount++
			}
			currentPkg = struct {
				Name        string
				Version     string
				Description string
				Section     string
				Filename    string
			}{}
			continue
		}

		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Package":
				currentPkg.Name = value
			case "Version":
				currentPkg.Version = value
			case "Description":
				currentPkg.Description = value
			case "Section":
				currentPkg.Section = value
			case "Filename":
				currentPkg.Filename = value
			}
		}
	}

	// Ne pas oublier le dernier package
	if currentPkg.Name != "" {
		_, err := stmt.Exec(
			currentPkg.Name,
			currentPkg.Version,
			currentPkg.Description,
			currentPkg.Section,
			release,
			component,
			arch,
			currentPkg.Filename,
			now,
		)
		if err != nil {
			return fmt.Errorf("failed to insert last package: %w", err)
		}
		packagesCount++
	}

	// Mettre à jour le statut d'indexation
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO index_status (release, component, architecture, last_indexed, packages_count)
		VALUES (?, ?, ?, ?, ?)
	`, release, component, arch, now, packagesCount)
	if err != nil {
		return fmt.Errorf("failed to update index status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// IndexContentsFile indexe un fichier Contents (pour la recherche par fichier)
func (ps *PackageSearchDB) IndexContentsFile(contentsPath, release, component, arch string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	file, err := os.Open(contentsPath)
	if err != nil {
		return fmt.Errorf("failed to open Contents file: %w", err)
	}
	defer file.Close()

	var reader *bufio.Scanner

	if strings.HasSuffix(contentsPath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = bufio.NewScanner(gzReader)
	} else if strings.HasSuffix(contentsPath, ".xz") {
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = bufio.NewScanner(xzReader)
	} else {
		reader = bufio.NewScanner(file)
	}

	// Buffer plus grand
	buf := make([]byte, 0, 64*1024)
	reader.Buffer(buf, 1024*1024)

	// Commencer une transaction
	tx, err := ps.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Supprimer les anciennes entrées
	_, err = tx.Exec("DELETE FROM package_files WHERE release = ? AND architecture = ?",
		release, arch)
	if err != nil {
		return fmt.Errorf("failed to delete old files: %w", err)
	}

	// Préparer le statement d'insertion
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO package_files
		(file_path, package_name, release, component, architecture)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	filesCount := 0

	for reader.Scan() {
		line := reader.Text()

		// Ignorer les lignes vides et les commentaires
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: FILE                                                    LOCATION
		// Le fichier et le package sont séparés par des espaces
		// La dernière colonne est le package (section/package ou juste package)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		filePath := parts[0]
		packageInfo := parts[len(parts)-1]

		// Le package peut être "section/packagename" ou juste "packagename"
		// Il peut aussi y avoir plusieurs packages séparés par des virgules
		packages := strings.Split(packageInfo, ",")
		for _, pkg := range packages {
			// Extraire le nom du package (après le /)
			pkgName := pkg
			pkgComponent := component
			if idx := strings.LastIndex(pkg, "/"); idx != -1 {
				pkgComponent = pkg[:idx]
				pkgName = pkg[idx+1:]
			}

			_, err := stmt.Exec(filePath, pkgName, release, pkgComponent, arch)
			if err != nil {
				// Ignorer les erreurs de duplicata
				continue
			}
			filesCount++
		}
	}

	// Mettre à jour le statut
	_, err = tx.Exec(`
		UPDATE index_status SET files_count = ?, last_indexed = ?
		WHERE release = ? AND component = ? AND architecture = ?
	`, filesCount, time.Now(), release, component, arch)
	if err != nil {
		// Ignorer si la mise à jour échoue
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// SearchOptions contient les options de recherche
type SearchOptions struct {
	Query        string // Terme de recherche
	SearchName   bool   // Chercher dans le nom du package
	SearchDesc   bool   // Chercher dans la description
	SearchFiles  bool   // Chercher dans les fichiers
	Release      string // Filtrer par release
	Component    string // Filtrer par composant
	Architecture string // Filtrer par architecture
	Limit        int    // Nombre max de résultats
	ExactMatch   bool   // Correspondance exacte (pas LIKE)
}

// Search effectue une recherche multi-critères
func (ps *PackageSearchDB) Search(opts SearchOptions) ([]*PackageSearchResult, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if opts.Query == "" {
		return nil, fmt.Errorf("search query cannot be empty")
	}

	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	// Si aucun type de recherche n'est spécifié, chercher partout
	if !opts.SearchName && !opts.SearchDesc && !opts.SearchFiles {
		opts.SearchName = true
		opts.SearchDesc = true
		opts.SearchFiles = true
	}

	var results []*PackageSearchResult
	seen := make(map[string]bool) // Pour éviter les doublons

	searchPattern := opts.Query
	if !opts.ExactMatch {
		searchPattern = "%" + opts.Query + "%"
	}

	// Recherche par nom de package
	if opts.SearchName {
		query := `
			SELECT package_name, version, description, section, release, component, architecture, filename
			FROM packages
			WHERE package_name LIKE ?
		`
		args := []interface{}{searchPattern}

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

		query += " ORDER BY package_name LIMIT ?"
		args = append(args, opts.Limit)

		rows, err := ps.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to search by name: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r PackageSearchResult
			var version, desc, section, filename sql.NullString
			err := rows.Scan(&r.PackageName, &version, &desc, &section,
				&r.Release, &r.Component, &r.Architecture, &filename)
			if err != nil {
				continue
			}
			if version.Valid {
				r.Version = version.String
			}
			if desc.Valid {
				r.Description = desc.String
			}
			if section.Valid {
				r.Section = section.String
			}
			if filename.Valid {
				r.Filename = filename.String
			}
			r.MatchType = "name"

			key := fmt.Sprintf("%s-%s-%s-%s", r.PackageName, r.Release, r.Component, r.Architecture)
			if !seen[key] {
				seen[key] = true
				results = append(results, &r)
			}
		}
	}

	// Recherche par description
	if opts.SearchDesc && len(results) < opts.Limit {
		query := `
			SELECT package_name, version, description, section, release, component, architecture, filename
			FROM packages
			WHERE description LIKE ?
		`
		args := []interface{}{searchPattern}

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

		query += " ORDER BY package_name LIMIT ?"
		args = append(args, opts.Limit-len(results))

		rows, err := ps.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to search by description: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r PackageSearchResult
			var version, desc, section, filename sql.NullString
			err := rows.Scan(&r.PackageName, &version, &desc, &section,
				&r.Release, &r.Component, &r.Architecture, &filename)
			if err != nil {
				continue
			}
			if version.Valid {
				r.Version = version.String
			}
			if desc.Valid {
				r.Description = desc.String
			}
			if section.Valid {
				r.Section = section.String
			}
			if filename.Valid {
				r.Filename = filename.String
			}
			r.MatchType = "description"

			key := fmt.Sprintf("%s-%s-%s-%s", r.PackageName, r.Release, r.Component, r.Architecture)
			if !seen[key] {
				seen[key] = true
				results = append(results, &r)
			}
		}
	}

	// Recherche par fichier (comme apt-file)
	if opts.SearchFiles && len(results) < opts.Limit {
		query := `
			SELECT pf.file_path, pf.package_name, pf.release, pf.component, pf.architecture,
			       p.version, p.description, p.section
			FROM package_files pf
			LEFT JOIN packages p ON pf.package_name = p.package_name
			                     AND pf.release = p.release
			                     AND pf.architecture = p.architecture
			WHERE pf.file_path LIKE ?
		`
		args := []interface{}{searchPattern}

		if opts.Release != "" {
			query += " AND pf.release = ?"
			args = append(args, opts.Release)
		}
		if opts.Architecture != "" {
			query += " AND pf.architecture = ?"
			args = append(args, opts.Architecture)
		}

		query += " ORDER BY pf.package_name LIMIT ?"
		args = append(args, opts.Limit-len(results))

		rows, err := ps.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to search by file: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r PackageSearchResult
			var filePath string
			var version, desc, section sql.NullString
			err := rows.Scan(&filePath, &r.PackageName, &r.Release, &r.Component, &r.Architecture,
				&version, &desc, &section)
			if err != nil {
				continue
			}
			if version.Valid {
				r.Version = version.String
			}
			if desc.Valid {
				r.Description = desc.String
			}
			if section.Valid {
				r.Section = section.String
			}
			r.MatchType = "file"
			r.MatchedFile = filePath

			key := fmt.Sprintf("%s-%s-%s-%s-%s", r.PackageName, r.Release, r.Component, r.Architecture, filePath)
			if !seen[key] {
				seen[key] = true
				results = append(results, &r)
			}
		}
	}

	return results, nil
}

// SearchByFile recherche les packages contenant un fichier spécifique
func (ps *PackageSearchDB) SearchByFile(filePath string, release, arch string, limit int) ([]*PackageSearchResult, error) {
	return ps.Search(SearchOptions{
		Query:        filePath,
		SearchFiles:  true,
		SearchName:   false,
		SearchDesc:   false,
		Release:      release,
		Architecture: arch,
		Limit:        limit,
	})
}

// SearchByName recherche les packages par nom
func (ps *PackageSearchDB) SearchByName(name string, release string, limit int) ([]*PackageSearchResult, error) {
	return ps.Search(SearchOptions{
		Query:       name,
		SearchName:  true,
		SearchDesc:  false,
		SearchFiles: false,
		Release:     release,
		Limit:       limit,
	})
}

// SearchByDescription recherche les packages par description
func (ps *PackageSearchDB) SearchByDescription(desc string, release string, limit int) ([]*PackageSearchResult, error) {
	return ps.Search(SearchOptions{
		Query:       desc,
		SearchName:  false,
		SearchDesc:  true,
		SearchFiles: false,
		Release:     release,
		Limit:       limit,
	})
}

// GetPackageFiles retourne tous les fichiers d'un package
func (ps *PackageSearchDB) GetPackageFiles(packageName, release, arch string) ([]string, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	query := `SELECT file_path FROM package_files WHERE package_name = ?`
	args := []interface{}{packageName}

	if release != "" {
		query += " AND release = ?"
		args = append(args, release)
	}
	if arch != "" {
		query += " AND architecture = ?"
		args = append(args, arch)
	}

	query += " ORDER BY file_path"

	rows, err := ps.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get package files: %w", err)
	}
	defer rows.Close()

	var files []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			continue
		}
		files = append(files, f)
	}

	return files, nil
}

// GetPackageInfo retourne les informations d'un package
func (ps *PackageSearchDB) GetPackageInfo(packageName, release, arch string) (*PackageSearchResult, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	query := `
		SELECT package_name, version, description, section, release, component, architecture, filename
		FROM packages
		WHERE package_name = ?
	`
	args := []interface{}{packageName}

	if release != "" {
		query += " AND release = ?"
		args = append(args, release)
	}
	if arch != "" {
		query += " AND architecture = ?"
		args = append(args, arch)
	}

	query += " LIMIT 1"

	var r PackageSearchResult
	var version, desc, section, filename sql.NullString
	err := ps.db.QueryRow(query, args...).Scan(
		&r.PackageName, &version, &desc, &section,
		&r.Release, &r.Component, &r.Architecture, &filename)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get package info: %w", err)
	}

	if version.Valid {
		r.Version = version.String
	}
	if desc.Valid {
		r.Description = desc.String
	}
	if section.Valid {
		r.Section = section.String
	}
	if filename.Valid {
		r.Filename = filename.String
	}

	return &r, nil
}

// GetIndexStatus retourne le statut de l'indexation
func (ps *PackageSearchDB) GetIndexStatus() ([]map[string]interface{}, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	rows, err := ps.db.Query(`
		SELECT release, component, architecture, last_indexed, packages_count, files_count
		FROM index_status
		ORDER BY release, component, architecture
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get index status: %w", err)
	}
	defer rows.Close()

	var status []map[string]interface{}
	for rows.Next() {
		var release, component, arch string
		var lastIndexed sql.NullTime
		var packagesCount, filesCount int64

		err := rows.Scan(&release, &component, &arch, &lastIndexed, &packagesCount, &filesCount)
		if err != nil {
			continue
		}

		entry := map[string]interface{}{
			"release":        release,
			"component":      component,
			"architecture":   arch,
			"packages_count": packagesCount,
			"files_count":    filesCount,
		}
		if lastIndexed.Valid {
			entry["last_indexed"] = lastIndexed.Time
		}
		status = append(status, entry)
	}

	return status, nil
}

// GetStats retourne des statistiques sur la base de recherche
func (ps *PackageSearchDB) GetSearchStats() (map[string]interface{}, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	stats := make(map[string]interface{})

	// Compter les packages
	var packagesCount int64
	err := ps.db.QueryRow("SELECT COUNT(*) FROM packages").Scan(&packagesCount)
	if err != nil {
		return nil, err
	}
	stats["total_packages"] = packagesCount

	// Compter les fichiers
	var filesCount int64
	err = ps.db.QueryRow("SELECT COUNT(*) FROM package_files").Scan(&filesCount)
	if err != nil {
		return nil, err
	}
	stats["total_files"] = filesCount

	// Dernière indexation
	var lastIndexed sql.NullTime
	err = ps.db.QueryRow("SELECT MAX(last_indexed) FROM index_status").Scan(&lastIndexed)
	if err == nil && lastIndexed.Valid {
		stats["last_indexed"] = lastIndexed.Time
	}

	return stats, nil
}

// Close ferme la connexion à la base de données
func (ps *PackageSearchDB) Close() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.db != nil {
		return ps.db.Close()
	}
	return nil
}

// GetDBPath retourne le chemin de la base de données
func (ps *PackageSearchDB) GetDBPath() string {
	return ps.dbPath
}
