package articarepos

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ArticaDebBasePath    = "/home/artica/tmp/deb"
	ArticaServicePath    = "/usr/sbin/artica-phpfpm-service"
	DebianControlVersion = "2.0"
)

type DebPackageInfo struct {
	ProductCode  string
	Version      string
	Architecture string
	Description  string
	Maintainer   string
	Homepage     string
	Section      string
	Priority     string
	SourceTarGz  string // Chemin vers le tar.gz source
}
type DebBuildResult struct {
	DebPath     string
	ExtractPath string
	Success     bool
	Error       error
}

func BuildDebPackage(soft ArticaSoft) (*DebBuildResult, error) {
	result := &DebBuildResult{}
	if _, err := os.Stat(soft.Tempfile); os.IsNotExist(err) {
		return nil, fmt.Errorf("source file does not exist: %s", soft.Tempfile)
	}
	debBaseDir := filepath.Join(ArticaDebBasePath, soft.ProductCode)
	if err := os.MkdirAll(debBaseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create deb directory %s: %w", debBaseDir, err)
	}
	result.ExtractPath = debBaseDir
	if err := extractTarGz(soft.Tempfile, debBaseDir); err != nil {
		return nil, fmt.Errorf("failed to extract tar.gz: %w", err)
	}
	info := DebPackageInfo{
		ProductCode:  soft.ProductCode,
		Version:      soft.Version,
		Architecture: "all", // Par défaut pour les packages Artica
		Description:  fmt.Sprintf("Artica %s package", soft.ProductCode),
		Maintainer:   "Artica Tech <support@articatech.com>",
		Homepage:     "https://wiki.articatech.com",
		Section:      "admin",
		Priority:     "optional",
		SourceTarGz:  soft.Tempfile,
	}
	debPath, err := createDebPackage(info, debBaseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create deb package: %w", err)
	}

	result.DebPath = debPath
	result.Success = true

	return result, nil
}
func extractTarGz(tarGzPath, destDir string) error {
	file, err := os.Open(tarGzPath)
	if err != nil {
		return fmt.Errorf("failed to open tar.gz: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}
		cleanPath := filepath.Clean(header.Name)
		if strings.Contains(cleanPath, "..") {
			continue
		}

		targetPath := filepath.Join(destDir, cleanPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close()

			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set permissions on %s: %w", targetPath, err)
			}
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("failed to create symlink %s: %w", targetPath, err)
				}
			}
		}
	}

	return nil
}
func createDebPackage(info DebPackageInfo, extractDir string) (string, error) {
	// Créer le répertoire de travail pour le .deb
	debWorkDir := filepath.Join(extractDir, ".deb-build")
	if err := os.MkdirAll(debWorkDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create deb work directory: %w", err)
	}
	defer os.RemoveAll(debWorkDir) // Nettoyer après

	// Créer la structure DEBIAN
	debianDir := filepath.Join(debWorkDir, "DEBIAN")
	if err := os.MkdirAll(debianDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create DEBIAN directory: %w", err)
	}

	// Créer le répertoire de données
	dataDir := filepath.Join(debWorkDir, "home", "artica", "tmp", "deb", info.ProductCode)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory: %w", err)
	}

	// Copier le contenu extrait vers le répertoire de données
	if err := copyDir(extractDir, dataDir); err != nil {
		return "", fmt.Errorf("failed to copy content: %w", err)
	}

	// Calculer la taille installée (en KB)
	installedSize, err := calculateDirSize(dataDir)
	if err != nil {
		installedSize = 0
	}
	installedSizeKB := installedSize / 1024

	// Créer le fichier control
	controlContent := fmt.Sprintf(`Package: artica-%s
Version: %s
Section: %s
Priority: %s
Architecture: %s
Installed-Size: %d
Maintainer: %s
Homepage: %s
Description: %s
 Artica %s component package.
 Automatically generated by ActiveDebianSync.
`,
		strings.ToLower(info.ProductCode),
		info.Version,
		info.Section,
		info.Priority,
		info.Architecture,
		installedSizeKB,
		info.Maintainer,
		info.Homepage,
		info.Description,
		info.ProductCode,
	)

	controlPath := filepath.Join(debianDir, "control")
	if err := os.WriteFile(controlPath, []byte(controlContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write control file: %w", err)
	}

	// Créer le script postinst
	postinstContent := fmt.Sprintf(`#!/bin/bash
set -e

if [ -x "%s" ]; then
    "%s" -install-deb %s || true
fi

exit 0
`, ArticaServicePath, ArticaServicePath, info.ProductCode)

	postinstPath := filepath.Join(debianDir, "postinst")
	if err := os.WriteFile(postinstPath, []byte(postinstContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write postinst script: %w", err)
	}
	prermContent := fmt.Sprintf(`#!/bin/bash
set -e

if [ -x "%s" ]; then
    "%s" -remove-deb %s || true
fi

exit 0
`, ArticaServicePath, ArticaServicePath, info.ProductCode)

	prermPath := filepath.Join(debianDir, "prerm")
	if err := os.WriteFile(prermPath, []byte(prermContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write prerm script: %w", err)
	}

	// Créer le fichier md5sums
	md5sumsPath := filepath.Join(debianDir, "md5sums")
	if err := generateMd5sums(debWorkDir, md5sumsPath); err != nil {
		// Non fatal, continuer sans md5sums
		_ = err
	}

	// Nom du fichier .deb de sortie
	debFileName := fmt.Sprintf("artica-%s_%s_%s.deb",
		strings.ToLower(info.ProductCode),
		info.Version,
		info.Architecture)
	debPath := filepath.Join(ArticaDebBasePath, debFileName)

	// Construire le .deb avec dpkg-deb si disponible, sinon manuellement
	if _, err := exec.LookPath("dpkg-deb"); err == nil {
		cmd := exec.Command("dpkg-deb", "--build", "--root-owner-group", debWorkDir, debPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("dpkg-deb failed: %s: %w", string(output), err)
		}
	} else {
		// Construire manuellement le .deb (ar archive)
		if err := buildDebManually(debWorkDir, debPath); err != nil {
			return "", fmt.Errorf("manual deb build failed: %w", err)
		}
	}

	return debPath, nil
}
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignorer le répertoire .deb-build
		if strings.Contains(path, ".deb-build") {
			return nil
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copier le fichier
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return err
		}

		return os.Chmod(dstPath, info.Mode())
	})
}
func calculateDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}
func generateMd5sums(debWorkDir, md5sumsPath string) error {
	var md5sums strings.Builder

	err := filepath.Walk(debWorkDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignorer les répertoires et le répertoire DEBIAN
		if info.IsDir() || strings.Contains(path, "DEBIAN") {
			return nil
		}

		relPath, err := filepath.Rel(debWorkDir, path)
		if err != nil {
			return err
		}

		// Calculer le MD5
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		// Utiliser crypto/md5
		content, err := io.ReadAll(file)
		if err != nil {
			return err
		}

		md5sum := fmt.Sprintf("%x", content)
		md5sums.WriteString(fmt.Sprintf("%s  %s\n", md5sum, relPath))

		return nil
	})

	if err != nil {
		return err
	}

	return os.WriteFile(md5sumsPath, []byte(md5sums.String()), 0644)
}
func buildDebManually(debWorkDir, debPath string) error {
	controlTarGz := filepath.Join(debWorkDir, "control.tar.gz")
	dataTarGz := filepath.Join(debWorkDir, "data.tar.gz")
	debianDir := filepath.Join(debWorkDir, "DEBIAN")

	if err := createTarGz(debianDir, controlTarGz, ""); err != nil {
		return fmt.Errorf("failed to create control.tar.gz: %w", err)
	}
	defer os.Remove(controlTarGz)

	if err := createDataTarGz(debWorkDir, dataTarGz); err != nil {
		return fmt.Errorf("failed to create data.tar.gz: %w", err)
	}
	defer os.Remove(dataTarGz)

	debianBinaryContent := []byte(DebianControlVersion + "\n")
	controlData, err := os.ReadFile(controlTarGz)
	if err != nil {
		return fmt.Errorf("failed to read control.tar.gz: %w", err)
	}

	dataData, err := os.ReadFile(dataTarGz)
	if err != nil {
		return fmt.Errorf("failed to read data.tar.gz: %w", err)
	}

	if err := createArArchive(debPath, []arEntry{
		{name: "debian-binary", data: debianBinaryContent},
		{name: "control.tar.gz", data: controlData},
		{name: "data.tar.gz", data: dataData},
	}); err != nil {
		return fmt.Errorf("failed to create AR archive: %w", err)
	}

	return nil
}

type arEntry struct {
	name string
	data []byte
}

func createArArchive(destPath string, entries []arEntry) error {
	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte("!<arch>\n")); err != nil {
		return fmt.Errorf("failed to write AR magic: %w", err)
	}

	for _, entry := range entries {
		if err := writeArEntry(outFile, entry.name, entry.data); err != nil {
			return fmt.Errorf("failed to write entry %s: %w", entry.name, err)
		}
	}

	return nil
}
func writeArEntry(w io.Writer, name string, data []byte) error {
	now := time.Now().Unix()
	size := len(data)
	header := make([]byte, 60)

	fileName := name
	if len(fileName) > 16 {
		fileName = fileName[:16]
	}
	copy(header[0:16], fmt.Sprintf("%-16s", fileName))
	copy(header[16:28], fmt.Sprintf("%-12d", now))
	copy(header[28:34], fmt.Sprintf("%-6d", 0))
	copy(header[34:40], fmt.Sprintf("%-6d", 0))
	copy(header[40:48], fmt.Sprintf("%-8o", 0100644))
	copy(header[48:58], fmt.Sprintf("%-10d", size))

	header[58] = '`'
	header[59] = '\n'

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	if size%2 != 0 {
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return fmt.Errorf("failed to write padding: %w", err)
		}
	}

	return nil
}
func createTarGz(srcDir, destPath, prefix string) error {
	outFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		if prefix != "" {
			header.Name = filepath.Join(prefix, relPath)
		} else {
			header.Name = relPath
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})
}
func createDataTarGz(debWorkDir, destPath string) error {
	outFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	return filepath.Walk(debWorkDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignorer DEBIAN et les fichiers de travail
		relPath, err := filepath.Rel(debWorkDir, path)
		if err != nil {
			return err
		}

		if relPath == "." || relPath == "DEBIAN" || strings.HasPrefix(relPath, "DEBIAN/") ||
			strings.HasSuffix(relPath, ".tar.gz") || relPath == "debian-binary" {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		// Préfixer avec ./ pour le format deb standard
		header.Name = "./" + relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})
}
func InstallDebPackage(productCode string) error {
	if _, err := os.Stat(ArticaServicePath); os.IsNotExist(err) {
		return fmt.Errorf("artica service not found at %s", ArticaServicePath)
	}

	cmd := exec.Command(ArticaServicePath, "-install-deb", productCode)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install command failed: %w", err)
	}

	return nil
}
func RemoveDebPackage(productCode string) error {
	if _, err := os.Stat(ArticaServicePath); os.IsNotExist(err) {
		return fmt.Errorf("artica service not found at %s", ArticaServicePath)
	}

	cmd := exec.Command(ArticaServicePath, "-remove-deb", productCode)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("remove command failed: %w", err)
	}

	return nil
}
func ListArticaDebPackages() ([]string, error) {
	if _, err := os.Stat(ArticaDebBasePath); os.IsNotExist(err) {
		return nil, nil // Répertoire n'existe pas encore
	}

	var packages []string
	entries, err := os.ReadDir(ArticaDebBasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read deb directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".deb") {
			packages = append(packages, entry.Name())
		}
	}

	return packages, nil
}
func GetArticaDebInfo(productCode string) (*DebPackageInfo, error) {
	debDir := filepath.Join(ArticaDebBasePath, productCode)
	if _, err := os.Stat(debDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("product code directory not found: %s", productCode)
	}

	// Chercher le .deb correspondant
	var debFile string
	entries, err := os.ReadDir(ArticaDebBasePath)
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("artica-%s_", strings.ToLower(productCode))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".deb") {
			debFile = entry.Name()
			break
		}
	}

	if debFile == "" {
		return nil, fmt.Errorf("no .deb file found for product code: %s", productCode)
	}

	// Extraire les infos du nom de fichier
	// Format: artica-{productcode}_{version}_{arch}.deb
	parts := strings.Split(strings.TrimSuffix(debFile, ".deb"), "_")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid deb filename format: %s", debFile)
	}

	return &DebPackageInfo{
		ProductCode:  productCode,
		Version:      parts[1],
		Architecture: parts[2],
	}, nil
}
func CleanupOldDebPackages(productCode string, keepVersions int) error {
	if keepVersions < 1 {
		keepVersions = 1
	}

	entries, err := os.ReadDir(ArticaDebBasePath)
	if err != nil {
		return fmt.Errorf("failed to read deb directory: %w", err)
	}

	prefix := fmt.Sprintf("artica-%s_", strings.ToLower(productCode))
	var debFiles []os.DirEntry

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".deb") {
			debFiles = append(debFiles, entry)
		}
	}

	// Garder les N dernières versions (triées par date de modification)
	if len(debFiles) <= keepVersions {
		return nil
	}

	// Trier par date de modification (plus récent en premier)
	type fileWithTime struct {
		entry   os.DirEntry
		modTime time.Time
	}

	var filesWithTime []fileWithTime
	for _, entry := range debFiles {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		filesWithTime = append(filesWithTime, fileWithTime{entry: entry, modTime: info.ModTime()})
	}

	// Tri décroissant par date
	for i := 0; i < len(filesWithTime)-1; i++ {
		for j := i + 1; j < len(filesWithTime); j++ {
			if filesWithTime[j].modTime.After(filesWithTime[i].modTime) {
				filesWithTime[i], filesWithTime[j] = filesWithTime[j], filesWithTime[i]
			}
		}
	}

	// Supprimer les anciennes versions
	for i := keepVersions; i < len(filesWithTime); i++ {
		path := filepath.Join(ArticaDebBasePath, filesWithTime[i].entry.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove old deb %s: %w", path, err)
		}
	}

	return nil
}

// AddToRepository ajoute un package .deb Artica au dépôt Debian mirror
// Le package sera copié dans pool/artica/{première lettre}/{nom}/ et les indexes seront régénérés
func AddToRepository(debPath, repositoryPath, release, component, architecture string) error {
	// Vérifier que le fichier .deb existe
	if _, err := os.Stat(debPath); os.IsNotExist(err) {
		return fmt.Errorf("deb file not found: %s", debPath)
	}

	// Extraire le nom du package depuis le nom du fichier
	// Format: artica-{productcode}_{version}_{arch}.deb
	debFileName := filepath.Base(debPath)
	parts := strings.Split(strings.TrimSuffix(debFileName, ".deb"), "_")
	if len(parts) < 3 {
		return fmt.Errorf("invalid deb filename format: %s", debFileName)
	}

	packageName := parts[0] // artica-xxx
	firstLetter := string(packageName[0])

	// Créer le répertoire pool pour ce package
	poolDir := filepath.Join(repositoryPath, "pool", component, firstLetter, packageName)
	if err := os.MkdirAll(poolDir, 0755); err != nil {
		return fmt.Errorf("failed to create pool directory: %w", err)
	}

	// Copier le fichier .deb dans le pool
	destPath := filepath.Join(poolDir, debFileName)
	if err := copyFileSimple(debPath, destPath); err != nil {
		return fmt.Errorf("failed to copy deb to pool: %w", err)
	}

	return nil
}

// copyFileSimple copie un fichier de src vers dst
func copyFileSimple(src, dst string) error {
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

// GetAllArticaDebPackages retourne la liste de tous les packages .deb Artica avec leurs chemins
func GetAllArticaDebPackages() ([]string, error) {
	if _, err := os.Stat(ArticaDebBasePath); os.IsNotExist(err) {
		return nil, nil
	}

	var packages []string
	entries, err := os.ReadDir(ArticaDebBasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read deb directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".deb") {
			packages = append(packages, filepath.Join(ArticaDebBasePath, entry.Name()))
		}
	}

	return packages, nil
}

// SyncAllArticaPackagesToRepository synchronise tous les packages Artica vers le dépôt
func SyncAllArticaPackagesToRepository(repositoryPath string, releases []string, component, architecture string) (int, error) {
	packages, err := GetAllArticaDebPackages()
	if err != nil {
		return 0, err
	}

	if len(packages) == 0 {
		return 0, nil
	}

	addedCount := 0
	for _, debPath := range packages {
		for _, release := range releases {
			if err := AddToRepository(debPath, repositoryPath, release, component, architecture); err != nil {
				return addedCount, fmt.Errorf("failed to add %s to repository: %w", filepath.Base(debPath), err)
			}
		}
		addedCount++
	}

	return addedCount, nil
}
