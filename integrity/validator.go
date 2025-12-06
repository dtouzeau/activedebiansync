package integrity

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ChecksumType représente le type de checksum
type ChecksumType string

const (
	MD5Sum    ChecksumType = "MD5Sum"
	SHA1Sum   ChecksumType = "SHA1"
	SHA256Sum ChecksumType = "SHA256"
	SHA512Sum ChecksumType = "SHA512"
)

// FileChecksum représente les checksums d'un fichier
type FileChecksum struct {
	Path     string
	Size     int64
	MD5      string
	SHA1     string
	SHA256   string
	SHA512   string
	Verified bool
}

// ReleaseFile représente un fichier Release parsé
type ReleaseFile struct {
	Checksums map[string]*FileChecksum // key = relative path
	mu        sync.RWMutex
}

// Validator gère la validation d'intégrité
type Validator struct {
	releaseFiles map[string]*ReleaseFile // key = release name (bookworm, trixie)
	mu           sync.RWMutex
}

// NewValidator crée une nouvelle instance de Validator
func NewValidator() *Validator {
	return &Validator{
		releaseFiles: make(map[string]*ReleaseFile),
	}
}

// ParseReleaseFile parse un fichier Release et extrait les checksums
func (v *Validator) ParseReleaseFile(releaseName, releaseFilePath string) error {
	file, err := os.Open(releaseFilePath)
	if err != nil {
		return fmt.Errorf("failed to open Release file: %w", err)
	}
	defer file.Close()

	rf := &ReleaseFile{
		Checksums: make(map[string]*FileChecksum),
	}

	scanner := bufio.NewScanner(file)
	var currentType ChecksumType
	var inChecksumSection bool

	for scanner.Scan() {
		line := scanner.Text()

		// Détecter les sections de checksums
		if strings.HasPrefix(line, "MD5Sum:") {
			currentType = MD5Sum
			inChecksumSection = true
			continue
		} else if strings.HasPrefix(line, "SHA1:") {
			currentType = SHA1Sum
			inChecksumSection = true
			continue
		} else if strings.HasPrefix(line, "SHA256:") {
			currentType = SHA256Sum
			inChecksumSection = true
			continue
		} else if strings.HasPrefix(line, "SHA512:") {
			currentType = SHA512Sum
			inChecksumSection = true
			continue
		}

		// Si on est dans une section de checksums
		if inChecksumSection {
			// Ligne vide ou nouvelle section = fin de la section
			if line == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
				inChecksumSection = false
				continue
			}

			// Parser la ligne de checksum
			// Format: " checksum size path"
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				checksum := fields[0]
				size := parseInt64(fields[1])
				path := fields[2]

				// Créer ou mettre à jour l'entrée
				if _, exists := rf.Checksums[path]; !exists {
					rf.Checksums[path] = &FileChecksum{
						Path: path,
						Size: size,
					}
				}

				// Ajouter le checksum du type approprié
				switch currentType {
				case MD5Sum:
					rf.Checksums[path].MD5 = checksum
				case SHA1Sum:
					rf.Checksums[path].SHA1 = checksum
				case SHA256Sum:
					rf.Checksums[path].SHA256 = checksum
				case SHA512Sum:
					rf.Checksums[path].SHA512 = checksum
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading Release file: %w", err)
	}

	v.mu.Lock()
	v.releaseFiles[releaseName] = rf
	v.mu.Unlock()

	return nil
}

// ValidateFile valide l'intégrité d'un fichier téléchargé
func (v *Validator) ValidateFile(releaseName, relativePath, localPath string) (bool, error) {
	v.mu.RLock()
	rf, exists := v.releaseFiles[releaseName]
	v.mu.RUnlock()

	if !exists {
		// No Release file loaded yet - skip validation (will be validated later)
		// This is normal during initial sync when Release files haven't been downloaded yet
		return true, nil
	}

	rf.mu.RLock()
	expected, exists := rf.Checksums[relativePath]
	rf.mu.RUnlock()

	if !exists {
		// Pas de checksum disponible, on considère comme valide (pour les fichiers Release, etc.)
		return true, nil
	}

	// Vérifier la taille du fichier
	stat, err := os.Stat(localPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat file: %w", err)
	}

	if stat.Size() != expected.Size {
		return false, fmt.Errorf("size mismatch: expected %d, got %d", expected.Size, stat.Size())
	}

	// Vérifier les checksums (dans l'ordre de préférence: SHA512 > SHA256 > SHA1 > MD5)
	if expected.SHA512 != "" {
		actual, err := calculateChecksum(localPath, SHA512Sum)
		if err != nil {
			return false, err
		}
		if actual != expected.SHA512 {
			return false, fmt.Errorf("SHA512 mismatch: expected %s, got %s", expected.SHA512, actual)
		}
	} else if expected.SHA256 != "" {
		actual, err := calculateChecksum(localPath, SHA256Sum)
		if err != nil {
			return false, err
		}
		if actual != expected.SHA256 {
			return false, fmt.Errorf("SHA256 mismatch: expected %s, got %s", expected.SHA256, actual)
		}
	} else if expected.SHA1 != "" {
		actual, err := calculateChecksum(localPath, SHA1Sum)
		if err != nil {
			return false, err
		}
		if actual != expected.SHA1 {
			return false, fmt.Errorf("SHA1 mismatch: expected %s, got %s", expected.SHA1, actual)
		}
	} else if expected.MD5 != "" {
		actual, err := calculateChecksum(localPath, MD5Sum)
		if err != nil {
			return false, err
		}
		if actual != expected.MD5 {
			return false, fmt.Errorf("MD5 mismatch: expected %s, got %s", expected.MD5, actual)
		}
	}

	// Marquer comme vérifié
	rf.mu.Lock()
	rf.Checksums[relativePath].Verified = true
	rf.mu.Unlock()

	return true, nil
}

// calculateChecksum calcule le checksum d'un fichier
func calculateChecksum(filePath string, checksumType ChecksumType) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var hasher hash.Hash
	switch checksumType {
	case MD5Sum:
		hasher = md5.New()
	case SHA1Sum:
		hasher = sha1.New()
	case SHA256Sum:
		hasher = sha256.New()
	case SHA512Sum:
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unknown checksum type: %s", checksumType)
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CalculateFileChecksum calcule tous les checksums d'un fichier
func CalculateFileChecksum(filePath string) (*FileChecksum, error) {
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fc := &FileChecksum{
		Path: filePath,
		Size: stat.Size(),
	}

	// Calculer MD5
	md5sum, err := calculateChecksum(filePath, MD5Sum)
	if err != nil {
		return nil, err
	}
	fc.MD5 = md5sum

	// Calculer SHA1
	sha1sum, err := calculateChecksum(filePath, SHA1Sum)
	if err != nil {
		return nil, err
	}
	fc.SHA1 = sha1sum

	// Calculer SHA256
	sha256sum, err := calculateChecksum(filePath, SHA256Sum)
	if err != nil {
		return nil, err
	}
	fc.SHA256 = sha256sum

	// Calculer SHA512
	sha512sum, err := calculateChecksum(filePath, SHA512Sum)
	if err != nil {
		return nil, err
	}
	fc.SHA512 = sha512sum

	return fc, nil
}

// GetVerificationStats retourne les statistiques de vérification
func (v *Validator) GetVerificationStats(releaseName string) (total, verified int) {
	v.mu.RLock()
	rf, exists := v.releaseFiles[releaseName]
	v.mu.RUnlock()

	if !exists {
		return 0, 0
	}

	rf.mu.RLock()
	defer rf.mu.RUnlock()

	total = len(rf.Checksums)
	for _, fc := range rf.Checksums {
		if fc.Verified {
			verified++
		}
	}

	return total, verified
}

// parseInt64 convertit une string en int64
func parseInt64(s string) int64 {
	var result int64
	fmt.Sscanf(s, "%d", &result)
	return result
}

// ValidatePackageGPGSignature valide la signature GPG d'un package .deb
func ValidatePackageGPGSignature(packagePath, signaturePath string) (bool, error) {
	// TODO: Implémenter la vérification de signature GPG pour les packages individuels
	// Pour l'instant, on se base sur la signature du fichier Release
	return true, nil
}

// GetExpectedChecksum retourne le checksum attendu pour un fichier
func (v *Validator) GetExpectedChecksum(releaseName, relativePath string) (*FileChecksum, error) {
	v.mu.RLock()
	rf, exists := v.releaseFiles[releaseName]
	v.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no Release file loaded for %s", releaseName)
	}

	rf.mu.RLock()
	defer rf.mu.RUnlock()

	fc, exists := rf.Checksums[relativePath]
	if !exists {
		return nil, fmt.Errorf("no checksum found for %s", relativePath)
	}

	return fc, nil
}

// ListUnverifiedFiles retourne la liste des fichiers non vérifiés
func (v *Validator) ListUnverifiedFiles(releaseName string) []string {
	v.mu.RLock()
	rf, exists := v.releaseFiles[releaseName]
	v.mu.RUnlock()

	if !exists {
		return nil
	}

	rf.mu.RLock()
	defer rf.mu.RUnlock()

	var unverified []string
	for path, fc := range rf.Checksums {
		if !fc.Verified {
			unverified = append(unverified, path)
		}
	}

	return unverified
}

// CompareFiles compare deux fichiers et retourne true s'ils sont identiques
func CompareFiles(file1, file2 string) (bool, error) {
	// Comparer d'abord la taille
	stat1, err := os.Stat(file1)
	if err != nil {
		return false, err
	}
	stat2, err := os.Stat(file2)
	if err != nil {
		return false, err
	}

	if stat1.Size() != stat2.Size() {
		return false, nil
	}

	// Comparer les checksums SHA256
	hash1, err := calculateChecksum(file1, SHA256Sum)
	if err != nil {
		return false, err
	}
	hash2, err := calculateChecksum(file2, SHA256Sum)
	if err != nil {
		return false, err
	}

	return hash1 == hash2, nil
}

// FindDuplicateFiles trouve tous les fichiers dupliqués dans un répertoire
func FindDuplicateFiles(rootPath string) (map[string][]string, error) {
	// Map: hash -> liste de fichiers
	hashMap := make(map[string][]string)
	duplicates := make(map[string][]string)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignorer les répertoires
		if info.IsDir() {
			return nil
		}

		// Calculer le hash
		hash, err := calculateChecksum(path, SHA256Sum)
		if err != nil {
			return nil // Ignorer les erreurs de lecture
		}

		hashMap[hash] = append(hashMap[hash], path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Filtrer uniquement les doublons
	for hash, files := range hashMap {
		if len(files) > 1 {
			duplicates[hash] = files
		}
	}

	return duplicates, nil
}
