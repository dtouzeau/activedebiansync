package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger gère les logs de l'application
type Logger struct {
	syncLog   *log.Logger
	accessLog *log.Logger
	syncFile  *os.File
	accessFile *os.File
	mu        sync.Mutex
}

var (
	globalLogger *Logger
	loggerOnce   sync.Once
)

// InitLogger initialise le système de logging
func InitLogger(syncLogPath, accessLogPath string) error {
	var initErr error

	loggerOnce.Do(func() {
		// Créer les répertoires si nécessaire
		if err := os.MkdirAll(filepath.Dir(syncLogPath), 0755); err != nil {
			initErr = fmt.Errorf("failed to create sync log directory: %w", err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(accessLogPath), 0755); err != nil {
			initErr = fmt.Errorf("failed to create access log directory: %w", err)
			return
		}

		// Ouvrir les fichiers de log
		syncFile, err := os.OpenFile(syncLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			initErr = fmt.Errorf("failed to open sync log file: %w", err)
			return
		}

		accessFile, err := os.OpenFile(accessLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			syncFile.Close()
			initErr = fmt.Errorf("failed to open access log file: %w", err)
			return
		}

		globalLogger = &Logger{
			syncLog:    log.New(syncFile, "", log.LstdFlags),
			accessLog:  log.New(accessFile, "", log.LstdFlags),
			syncFile:   syncFile,
			accessFile: accessFile,
		}
	})

	return initErr
}

// GetLogger retourne l'instance du logger
func GetLogger() *Logger {
	return globalLogger
}

// LogSync enregistre un message de synchronisation
func (l *Logger) LogSync(format string, v ...interface{}) {
	if l == nil || l.syncLog == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, v...)
	l.syncLog.Println(msg)
	// Afficher aussi sur stdout pour systemd
	fmt.Printf("[SYNC] %s: %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// LogAccess enregistre un accès HTTP
func (l *Logger) LogAccess(remoteAddr, method, uri string, statusCode int, bytesSent int64) {
	if l == nil || l.accessLog == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("%s - %s %s - %d - %d bytes", remoteAddr, method, uri, statusCode, bytesSent)
	l.accessLog.Println(msg)
}

// LogError enregistre une erreur
func (l *Logger) LogError(format string, v ...interface{}) {
	if l == nil || l.syncLog == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("[ERROR] "+format, v...)
	l.syncLog.Println(msg)
	fmt.Printf("[ERROR] %s: %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// LogInfo enregistre une information
func (l *Logger) LogInfo(format string, v ...interface{}) {
	if l == nil || l.syncLog == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("[INFO] "+format, v...)
	l.syncLog.Println(msg)
	fmt.Printf("[INFO] %s: %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// Close ferme les fichiers de log
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var err error
	if l.syncFile != nil {
		if e := l.syncFile.Close(); e != nil {
			err = e
		}
	}
	if l.accessFile != nil {
		if e := l.accessFile.Close(); e != nil {
			err = e
		}
	}
	return err
}
