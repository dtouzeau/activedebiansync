package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// User represents a web console user
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Salt         string     `json:"-"`
	Email        string     `json:"email,omitempty"`
	Role         string     `json:"role"`
	Active       bool       `json:"active"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// Session represents a user session
type Session struct {
	ID        string
	UserID    int64
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// UsersDB manages the users database for web console authentication
type UsersDB struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewUsersDB creates a new UsersDB instance
// dbDir is the directory where the database file will be stored
func NewUsersDB(dbDir string) (*UsersDB, error) {
	dbPath := filepath.Join(dbDir, "users.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open users database: %w", err)
	}

	// Create tables if they don't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT,
		role TEXT NOT NULL DEFAULT 'user',
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	usersDB := &UsersDB{
		db:     db,
		dbPath: dbPath,
	}

	// Check if there are any users, if not create default admin
	count, err := usersDB.CountUsers()
	if err == nil && count == 0 {
		// Create default admin user (password: admin)
		if err := usersDB.CreateUser("admin", "admin", "admin@localhost", "admin"); err != nil {
			// Log but don't fail
			fmt.Fprintf(os.Stderr, "Warning: failed to create default admin user: %v\n", err)
		}
	}

	return usersDB, nil
}

// generateSalt generates a random salt
func generateSalt() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashPassword hashes a password with salt
func hashPassword(password, salt string) string {
	hash := sha256.New()
	hash.Write([]byte(password + salt))
	return hex.EncodeToString(hash.Sum(nil))
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateUser creates a new user
func (u *UsersDB) CreateUser(username, password, email, role string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	salt, err := generateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHash := hashPassword(password, salt)

	_, err = u.db.Exec(`
		INSERT INTO users (username, password_hash, salt, email, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, username, passwordHash, salt, email, role, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUser updates an existing user
func (u *UsersDB) UpdateUser(id int64, email, role string, active bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	_, err := u.db.Exec(`
		UPDATE users SET email = ?, role = ?, active = ?, updated_at = ?
		WHERE id = ?
	`, email, role, active, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password
func (u *UsersDB) UpdatePassword(id int64, newPassword string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	salt, err := generateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHash := hashPassword(newPassword, salt)

	_, err = u.db.Exec(`
		UPDATE users SET password_hash = ?, salt = ?, updated_at = ?
		WHERE id = ?
	`, passwordHash, salt, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// DeleteUser deletes a user by ID
func (u *UsersDB) DeleteUser(id int64) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// First delete all sessions for this user
	_, _ = u.db.Exec("DELETE FROM sessions WHERE user_id = ?", id)

	result, err := u.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUser retrieves a user by ID
func (u *UsersDB) GetUser(id int64) (*User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var user User
	var lastLogin sql.NullTime

	err := u.db.QueryRow(`
		SELECT id, username, password_hash, salt, email, role, active, created_at, updated_at, last_login
		FROM users WHERE id = ?
	`, id).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Salt, &user.Email,
		&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt, &lastLogin)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (u *UsersDB) GetUserByUsername(username string) (*User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var user User
	var lastLogin sql.NullTime
	var email sql.NullString

	err := u.db.QueryRow(`
		SELECT id, username, password_hash, salt, email, role, active, created_at, updated_at, last_login
		FROM users WHERE username = ?
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Salt, &email,
		&user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt, &lastLogin)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if email.Valid {
		user.Email = email.String
	}

	return &user, nil
}

// ListUsers returns all users
func (u *UsersDB) ListUsers() ([]*User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	rows, err := u.db.Query(`
		SELECT id, username, email, role, active, created_at, updated_at, last_login
		FROM users ORDER BY username
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var lastLogin sql.NullTime
		var email sql.NullString

		if err := rows.Scan(&user.ID, &user.Username, &email, &user.Role, &user.Active,
			&user.CreatedAt, &user.UpdatedAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}
		if email.Valid {
			user.Email = email.String
		}

		users = append(users, &user)
	}

	return users, nil
}

// CountUsers returns the number of users
func (u *UsersDB) CountUsers() (int64, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var count int64
	err := u.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// ValidateCredentials validates username and password
func (u *UsersDB) ValidateCredentials(username, password string) (*User, error) {
	user, err := u.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	if !user.Active {
		return nil, nil
	}

	// Verify password
	passwordHash := hashPassword(password, user.Salt)
	if passwordHash != user.PasswordHash {
		return nil, nil
	}

	// Update last login
	u.mu.Lock()
	_, _ = u.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)
	u.mu.Unlock()

	return user, nil
}

// CreateSession creates a new session for a user
func (u *UsersDB) CreateSession(userID int64, timeoutMinutes int) (*Session, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(timeoutMinutes) * time.Minute)

	_, err = u.db.Exec(`
		INSERT INTO sessions (id, user_id, created_at, expires_at)
		VALUES (?, ?, ?, ?)
	`, sessionID, userID, now, expiresAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Get user info for the session
	var username, role string
	err = u.db.QueryRow("SELECT username, role FROM users WHERE id = ?", userID).Scan(&username, &role)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

// GetSession retrieves a session by ID
func (u *UsersDB) GetSession(sessionID string) (*Session, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	var session Session
	err := u.db.QueryRow(`
		SELECT s.id, s.user_id, u.username, u.role, s.created_at, s.expires_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ? AND s.expires_at > ? AND u.active = 1
	`, sessionID, time.Now()).Scan(&session.ID, &session.UserID, &session.Username,
		&session.Role, &session.CreatedAt, &session.ExpiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// ExtendSession extends the expiration time of a session
func (u *UsersDB) ExtendSession(sessionID string, timeoutMinutes int) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	expiresAt := time.Now().Add(time.Duration(timeoutMinutes) * time.Minute)
	_, err := u.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", expiresAt, sessionID)
	if err != nil {
		return fmt.Errorf("failed to extend session: %w", err)
	}

	return nil
}

// DeleteSession deletes a session
func (u *UsersDB) DeleteSession(sessionID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	_, err := u.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// CleanExpiredSessions removes expired sessions
func (u *UsersDB) CleanExpiredSessions() (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	result, err := u.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to clean sessions: %w", err)
	}

	return result.RowsAffected()
}

// Close closes the database connection
func (u *UsersDB) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.db != nil {
		return u.db.Close()
	}
	return nil
}

// GetDBPath returns the database path
func (u *UsersDB) GetDBPath() string {
	return u.dbPath
}

// CreateOAuthSession creates a session for an OAuth-authenticated user
// If the user doesn't exist, it creates them as an OAuth user
func (u *UsersDB) CreateOAuthSession(username string, isAdmin bool, accessToken string, timeoutMinutes int) (*Session, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Check if user exists
	var userID int64
	var role string
	err := u.db.QueryRow("SELECT id, role FROM users WHERE username = ?", username).Scan(&userID, &role)

	if err == sql.ErrNoRows {
		// Create new OAuth user (no password)
		role = "user"
		if isAdmin {
			role = "admin"
		}

		result, err := u.db.Exec(`
			INSERT INTO users (username, password_hash, salt, role, active, created_at, updated_at)
			VALUES (?, 'oauth', 'oauth', ?, 1, ?, ?)
		`, username, role, time.Now(), time.Now())
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth user: %w", err)
		}

		userID, err = result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("failed to get user ID: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to check user: %w", err)
	} else {
		// Update role if admin status changed
		if isAdmin && role != "admin" {
			u.db.Exec("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?", time.Now(), userID)
			role = "admin"
		}
	}

	// Update last login
	u.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), userID)

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(timeoutMinutes) * time.Minute)

	_, err = u.db.Exec(`
		INSERT INTO sessions (id, user_id, created_at, expires_at)
		VALUES (?, ?, ?, ?)
	`, sessionID, userID, now, expiresAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}
