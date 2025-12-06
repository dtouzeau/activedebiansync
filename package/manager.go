package pkgmanager

import (
	"activedebiansync/config"
	"activedebiansync/utils"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
)

// GPGSigner interface pour la signature GPG
type GPGSigner interface {
	SignReleaseFile(releaseFilePath string) error
	IsEnabled() bool
}

// PackageManager gère les packages Debian personnalisés
type PackageManager struct {
	config     *config.Config
	logger     *utils.Logger
	gpgManager GPGSigner
}

// PackageInfo contient les métadonnées d'un package Debian
type PackageInfo struct {
	Package      string
	Version      string
	Architecture string
	Maintainer   string
	Description  string
	Filename     string
	Size         int64
	MD5sum       string
	SHA1         string
	SHA256       string
	Section      string
	Priority     string
	Depends      string
}

// NewPackageManager crée une nouvelle instance de PackageManager
func NewPackageManager(cfg *config.Config, logger *utils.Logger, gpgManager GPGSigner) *PackageManager {
	return &PackageManager{
		config:     cfg,
		logger:     logger,
		gpgManager: gpgManager,
	}
}

// AddPackage ajoute un package .deb au dépôt local
func (pm *PackageManager) AddPackage(debFilePath, release, component, architecture string) error {
	pm.logger.LogInfo("Adding custom package: %s to %s/%s/%s", debFilePath, release, component, architecture)

	// Vérifier que le fichier existe
	if _, err := os.Stat(debFilePath); os.IsNotExist(err) {
		return fmt.Errorf("package file not found: %s", debFilePath)
	}

	// Extraire les métadonnées du package
	pkgInfo, err := pm.extractPackageInfo(debFilePath)
	if err != nil {
		return fmt.Errorf("failed to extract package info: %w", err)
	}

	pm.logger.LogInfo("Package info: %s %s (%s)", pkgInfo.Package, pkgInfo.Version, pkgInfo.Architecture)

	// Vérifier que l'architecture correspond
	if pkgInfo.Architecture != architecture && pkgInfo.Architecture != "all" {
		return fmt.Errorf("architecture mismatch: package is %s, requested %s", pkgInfo.Architecture, architecture)
	}

	// Créer les répertoires nécessaires
	cfg := pm.config.Get()
	poolDir := filepath.Join(cfg.RepositoryPath, "pool", component, string(pkgInfo.Package[0]), pkgInfo.Package)
	if err := os.MkdirAll(poolDir, 0755); err != nil {
		return fmt.Errorf("failed to create pool directory: %w", err)
	}

	// Copier le fichier .deb dans le pool
	destFileName := fmt.Sprintf("%s_%s_%s.deb", pkgInfo.Package, pkgInfo.Version, pkgInfo.Architecture)
	destPath := filepath.Join(poolDir, destFileName)

	if err := pm.copyFile(debFilePath, destPath); err != nil {
		return fmt.Errorf("failed to copy package: %w", err)
	}

	pm.logger.LogInfo("Package copied to: %s", destPath)

	// Mettre à jour les chemins relatifs
	pkgInfo.Filename = filepath.Join("pool", component, string(pkgInfo.Package[0]), pkgInfo.Package, destFileName)

	// Régénérer les indexes
	if err := pm.RegenerateIndexes(release, component, architecture); err != nil {
		return fmt.Errorf("failed to regenerate indexes: %w", err)
	}

	pm.logger.LogInfo("Successfully added package %s %s", pkgInfo.Package, pkgInfo.Version)
	return nil
}

// RemovePackage supprime un package du dépôt
func (pm *PackageManager) RemovePackage(packageName, version, release, component, architecture string) error {
	pm.logger.LogInfo("Removing package: %s %s from %s/%s/%s", packageName, version, release, component, architecture)

	cfg := pm.config.Get()
	poolDir := filepath.Join(cfg.RepositoryPath, "pool", component, string(packageName[0]), packageName)
	debFileName := fmt.Sprintf("%s_%s_%s.deb", packageName, version, architecture)
	debPath := filepath.Join(poolDir, debFileName)

	// Supprimer le fichier .deb
	if err := os.Remove(debPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove package: %w", err)
		}
	}

	pm.logger.LogInfo("Package file removed: %s", debPath)

	// Régénérer les indexes
	if err := pm.RegenerateIndexes(release, component, architecture); err != nil {
		return fmt.Errorf("failed to regenerate indexes: %w", err)
	}

	pm.logger.LogInfo("Successfully removed package %s %s", packageName, version)
	return nil
}

// RegenerateIndexes régénère les fichiers Packages et Release
func (pm *PackageManager) RegenerateIndexes(release, component, architecture string) error {
	pm.logger.LogInfo("Regenerating indexes for %s/%s/%s", release, component, architecture)

	cfg := pm.config.Get()

	// Générer le fichier Packages
	packagesPath := filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("binary-%s", architecture), "Packages")
	if err := pm.generatePackagesFile(release, component, architecture, packagesPath); err != nil {
		return fmt.Errorf("failed to generate Packages file: %w", err)
	}

	// Compresser en .gz
	if err := pm.compressGzip(packagesPath, packagesPath+".gz"); err != nil {
		return fmt.Errorf("failed to compress Packages.gz: %w", err)
	}

	// Compresser en .xz
	if err := pm.compressXZ(packagesPath, packagesPath+".xz"); err != nil {
		return fmt.Errorf("failed to compress Packages.xz: %w", err)
	}

	pm.logger.LogInfo("Generated Packages files")

	// Générer le fichier Release pour cette architecture
	releaseFilePath := filepath.Join(cfg.RepositoryPath, "dists", release, component, fmt.Sprintf("binary-%s", architecture), "Release")
	if err := pm.generateBinaryReleaseFile(release, component, architecture, releaseFilePath); err != nil {
		return fmt.Errorf("failed to generate Release file: %w", err)
	}

	pm.logger.LogInfo("Generated Release file")

	// Régénérer le Release principal de la distribution
	mainReleasePath := filepath.Join(cfg.RepositoryPath, "dists", release, "Release")
	if err := pm.generateDistributionRelease(release); err != nil {
		return fmt.Errorf("failed to generate distribution Release: %w", err)
	}

	// Signer le fichier Release avec GPG si activé
	if pm.gpgManager != nil && pm.gpgManager.IsEnabled() {
		pm.logger.LogInfo("Signing Release file with GPG")
		if err := pm.gpgManager.SignReleaseFile(mainReleasePath); err != nil {
			pm.logger.LogError("Failed to sign Release file: %v", err)
			// Ne pas échouer complètement si la signature échoue
		} else {
			pm.logger.LogInfo("Release file signed successfully")
		}
	}

	pm.logger.LogInfo("Successfully regenerated all indexes")
	return nil
}

// extractPackageInfo extrait les métadonnées d'un fichier .deb
func (pm *PackageManager) extractPackageInfo(debFilePath string) (*PackageInfo, error) {
	// Utiliser dpkg-deb pour extraire les informations
	cmd := exec.Command("dpkg-deb", "-f", debFilePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-deb failed: %w", err)
	}

	// Parser la sortie
	pkgInfo := &PackageInfo{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Package":
				pkgInfo.Package = value
			case "Version":
				pkgInfo.Version = value
			case "Architecture":
				pkgInfo.Architecture = value
			case "Maintainer":
				pkgInfo.Maintainer = value
			case "Description":
				pkgInfo.Description = value
			case "Section":
				pkgInfo.Section = value
			case "Priority":
				pkgInfo.Priority = value
			case "Depends":
				pkgInfo.Depends = value
			}
		}
	}

	// Calculer les checksums
	if err := pm.calculateChecksums(debFilePath, pkgInfo); err != nil {
		return nil, fmt.Errorf("failed to calculate checksums: %w", err)
	}

	// Obtenir la taille du fichier
	stat, err := os.Stat(debFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	pkgInfo.Size = stat.Size()

	return pkgInfo, nil
}

// calculateChecksums calcule les checksums MD5, SHA1 et SHA256
func (pm *PackageManager) calculateChecksums(filePath string, pkgInfo *PackageInfo) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	if _, err := io.Copy(io.MultiWriter(md5Hash, sha1Hash, sha256Hash), file); err != nil {
		return err
	}

	pkgInfo.MD5sum = hex.EncodeToString(md5Hash.Sum(nil))
	pkgInfo.SHA1 = hex.EncodeToString(sha1Hash.Sum(nil))
	pkgInfo.SHA256 = hex.EncodeToString(sha256Hash.Sum(nil))

	return nil
}

// generatePackagesFile génère le fichier Packages
func (pm *PackageManager) generatePackagesFile(release, component, architecture, outputPath string) error {
	cfg := pm.config.Get()

	// Créer le répertoire si nécessaire
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	// Scanner le pool pour trouver tous les .deb
	poolDir := filepath.Join(cfg.RepositoryPath, "pool", component)
	var packages []*PackageInfo

	err := filepath.Walk(poolDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continuer même en cas d'erreur
		}

		if !info.IsDir() && strings.HasSuffix(path, ".deb") {
			pkgInfo, err := pm.extractPackageInfo(path)
			if err != nil {
				pm.logger.LogError("Failed to extract info from %s: %v", path, err)
				return nil // Continuer
			}

			// Vérifier l'architecture
			if pkgInfo.Architecture == architecture || pkgInfo.Architecture == "all" {
				// Calculer le chemin relatif
				relPath, err := filepath.Rel(cfg.RepositoryPath, path)
				if err != nil {
					return err
				}
				pkgInfo.Filename = relPath
				packages = append(packages, pkgInfo)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Trier les packages par nom
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Package < packages[j].Package
	})

	// Écrire le fichier Packages
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, pkg := range packages {
		fmt.Fprintf(writer, "Package: %s\n", pkg.Package)
		fmt.Fprintf(writer, "Version: %s\n", pkg.Version)
		fmt.Fprintf(writer, "Architecture: %s\n", pkg.Architecture)
		if pkg.Section != "" {
			fmt.Fprintf(writer, "Section: %s\n", pkg.Section)
		}
		if pkg.Priority != "" {
			fmt.Fprintf(writer, "Priority: %s\n", pkg.Priority)
		}
		if pkg.Maintainer != "" {
			fmt.Fprintf(writer, "Maintainer: %s\n", pkg.Maintainer)
		}
		if pkg.Depends != "" {
			fmt.Fprintf(writer, "Depends: %s\n", pkg.Depends)
		}
		fmt.Fprintf(writer, "Filename: %s\n", pkg.Filename)
		fmt.Fprintf(writer, "Size: %d\n", pkg.Size)
		fmt.Fprintf(writer, "MD5sum: %s\n", pkg.MD5sum)
		fmt.Fprintf(writer, "SHA1: %s\n", pkg.SHA1)
		fmt.Fprintf(writer, "SHA256: %s\n", pkg.SHA256)
		if pkg.Description != "" {
			fmt.Fprintf(writer, "Description: %s\n", pkg.Description)
		}
		fmt.Fprintf(writer, "\n")
	}

	return writer.Flush()
}

// generateBinaryReleaseFile génère le fichier Release pour une architecture
func (pm *PackageManager) generateBinaryReleaseFile(release, component, architecture, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "Archive: %s\n", release)
	fmt.Fprintf(writer, "Component: %s\n", component)
	fmt.Fprintf(writer, "Origin: ActiveDebianSync\n")
	fmt.Fprintf(writer, "Label: ActiveDebianSync Custom Repository\n")
	fmt.Fprintf(writer, "Architecture: %s\n", architecture)

	return writer.Flush()
}

// generateDistributionRelease génère le fichier Release principal de la distribution
func (pm *PackageManager) generateDistributionRelease(release string) error {
	cfg := pm.config.Get()
	releasePath := filepath.Join(cfg.RepositoryPath, "dists", release, "Release")

	file, err := os.Create(releasePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "Origin: ActiveDebianSync\n")
	fmt.Fprintf(writer, "Label: ActiveDebianSync Custom Repository\n")
	fmt.Fprintf(writer, "Suite: %s\n", release)
	fmt.Fprintf(writer, "Codename: %s\n", release)
	fmt.Fprintf(writer, "Date: %s\n", time.Now().UTC().Format(time.RFC1123))
	fmt.Fprintf(writer, "Architectures: %s\n", strings.Join(cfg.DebianArchs, " "))
	fmt.Fprintf(writer, "Components: %s\n", strings.Join(cfg.DebianComponents, " "))
	fmt.Fprintf(writer, "Description: ActiveDebianSync Custom Repository\n")

	// Calculer les checksums des fichiers dans dists/
	fmt.Fprintf(writer, "MD5Sum:\n")
	fmt.Fprintf(writer, "SHA1:\n")
	fmt.Fprintf(writer, "SHA256:\n")

	// TODO: Ajouter les checksums réels des fichiers Packages, Packages.gz, etc.

	return writer.Flush()
}

// compressGzip compresse un fichier en gzip
func (pm *PackageManager) compressGzip(inputPath, outputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	gzipWriter := gzip.NewWriter(output)
	defer gzipWriter.Close()

	_, err = io.Copy(gzipWriter, input)
	return err
}

// compressXZ compresse un fichier en xz
func (pm *PackageManager) compressXZ(inputPath, outputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()

	xzWriter, err := xz.NewWriter(output)
	if err != nil {
		return err
	}
	defer xzWriter.Close()

	_, err = io.Copy(xzWriter, input)
	return err
}

// copyFile copie un fichier
func (pm *PackageManager) copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// ListPackages liste tous les packages personnalisés
func (pm *PackageManager) ListPackages(release, component, architecture string) ([]*PackageInfo, error) {
	cfg := pm.config.Get()
	poolDir := filepath.Join(cfg.RepositoryPath, "pool", component)
	var packages []*PackageInfo

	err := filepath.Walk(poolDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && strings.HasSuffix(path, ".deb") {
			pkgInfo, err := pm.extractPackageInfo(path)
			if err != nil {
				return nil
			}

			if pkgInfo.Architecture == architecture || pkgInfo.Architecture == "all" {
				packages = append(packages, pkgInfo)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return packages, nil
}
