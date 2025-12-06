package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// PIDFile gère le fichier PID du démon
type PIDFile struct {
	path string
}

// NewPIDFile crée une nouvelle instance de PIDFile
func NewPIDFile(path string) *PIDFile {
	return &PIDFile{path: path}
}

// Write écrit le PID actuel dans le fichier
func (p *PIDFile) Write() error {
	// Créer le répertoire parent si nécessaire
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	// Vérifier si un fichier PID existe déjà
	if err := p.checkExisting(); err != nil {
		return err
	}

	// Écrire le PID actuel
	pid := os.Getpid()
	content := fmt.Sprintf("%d\n", pid)

	if err := os.WriteFile(p.path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	return nil
}

// Remove supprime le fichier PID
func (p *PIDFile) Remove() error {
	if err := os.Remove(p.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PID file: %w", err)
	}
	return nil
}

// Read lit le PID depuis le fichier
func (p *PIDFile) Read() (int, error) {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return 0, fmt.Errorf("failed to read PID file: %w", err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID in file: %w", err)
	}

	return pid, nil
}

// checkExisting vérifie si un processus est déjà en cours d'exécution
func (p *PIDFile) checkExisting() error {
	// Vérifier si le fichier existe
	if _, err := os.Stat(p.path); os.IsNotExist(err) {
		return nil // Pas de fichier, OK
	}

	// Lire le PID existant
	pid, err := p.Read()
	if err != nil {
		// Le fichier existe mais est invalide, on peut le remplacer
		return nil
	}

	// Vérifier si le processus existe toujours
	if isProcessRunning(pid) {
		return fmt.Errorf("daemon already running with PID %d", pid)
	}

	// Le processus n'existe plus, supprimer le fichier obsolète
	if err := p.Remove(); err != nil {
		return fmt.Errorf("failed to remove stale PID file: %w", err)
	}

	return nil
}

// isProcessRunning vérifie si un processus avec le PID donné est en cours d'exécution
func isProcessRunning(pid int) bool {
	// Envoyer le signal 0 pour vérifier l'existence du processus
	// Signal 0 ne fait rien mais vérifie si le processus existe
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Sur Unix, FindProcess retourne toujours un processus
	// Il faut tester avec Signal pour vérifier s'il existe vraiment
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		// ESRCH = No such process
		return false
	}

	return true
}

// GetPath retourne le chemin du fichier PID
func (p *PIDFile) GetPath() string {
	return p.path
}
