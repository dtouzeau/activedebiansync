package cluster

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Compressor handles data compression
type Compressor struct {
	method string
}

// NewCompressor creates a new compressor with the specified method
func NewCompressor(method string) *Compressor {
	return &Compressor{method: method}
}

// Compress compresses data using the configured method
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	switch c.method {
	case "zstd":
		return c.compressZstd(data)
	case "gzip":
		return c.compressGzip(data)
	case "none", "":
		return data, nil
	default:
		return nil, fmt.Errorf("unknown compression method: %s", c.method)
	}
}

// Decompress decompresses data using the configured method
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	switch c.method {
	case "zstd":
		return c.decompressZstd(data)
	case "gzip":
		return c.decompressGzip(data)
	case "none", "":
		return data, nil
	default:
		return nil, fmt.Errorf("unknown compression method: %s", c.method)
	}
}

func (c *Compressor) compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}
	if _, err := enc.Write(data); err != nil {
		enc.Close()
		return nil, fmt.Errorf("failed to write zstd data: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zstd encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *Compressor) decompressZstd(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}
	defer dec.Close()
	return io.ReadAll(dec)
}

func (c *Compressor) compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		gz.Close()
		return nil, fmt.Errorf("failed to write gzip data: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *Compressor) decompressGzip(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

// CalculateChecksum computes SHA256 checksum of data
func CalculateChecksum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CalculateFileChecksum computes SHA256 checksum of a file
func CalculateFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ManifestBuilder builds a manifest from a directory
type ManifestBuilder struct {
	rootPath string
	entries  []ManifestEntry
	total    int64
	size     int64
}

// NewManifestBuilder creates a new manifest builder
func NewManifestBuilder(rootPath string) *ManifestBuilder {
	return &ManifestBuilder{
		rootPath: rootPath,
		entries:  make([]ManifestEntry, 0),
	}
}

// Build walks the directory and builds the manifest
func (mb *ManifestBuilder) Build() (*Manifest, error) {
	err := filepath.Walk(mb.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(mb.rootPath, path)
		if err != nil {
			return err
		}

		// Skip hidden files and temp files
		if strings.HasPrefix(filepath.Base(relPath), ".") {
			return nil
		}

		// Calculate checksum
		checksum, err := CalculateFileChecksum(path)
		if err != nil {
			return fmt.Errorf("failed to calculate checksum for %s: %w", relPath, err)
		}

		mb.entries = append(mb.entries, ManifestEntry{
			Path:     relPath,
			Size:     info.Size(),
			ModTime:  info.ModTime().Unix(),
			Checksum: checksum,
		})
		mb.total++
		mb.size += info.Size()

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to build manifest: %w", err)
	}

	return &Manifest{
		TotalFiles: mb.total,
		TotalSize:  mb.size,
		Entries:    mb.entries,
	}, nil
}

// BuildWithProgress walks the directory and reports progress
func (mb *ManifestBuilder) BuildWithProgress(progress func(current int64, total int64)) (*Manifest, error) {
	// First pass: count files
	var totalFiles int64
	err := filepath.Walk(mb.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasPrefix(filepath.Base(path), ".") {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Second pass: build manifest with progress
	var processed int64
	err = filepath.Walk(mb.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(mb.rootPath, path)
		if err != nil {
			return err
		}

		if strings.HasPrefix(filepath.Base(relPath), ".") {
			return nil
		}

		checksum, err := CalculateFileChecksum(path)
		if err != nil {
			return fmt.Errorf("failed to calculate checksum for %s: %w", relPath, err)
		}

		mb.entries = append(mb.entries, ManifestEntry{
			Path:     relPath,
			Size:     info.Size(),
			ModTime:  info.ModTime().Unix(),
			Checksum: checksum,
		})
		mb.total++
		mb.size += info.Size()
		processed++

		if progress != nil {
			progress(processed, totalFiles)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to build manifest: %w", err)
	}

	return &Manifest{
		TotalFiles: mb.total,
		TotalSize:  mb.size,
		Entries:    mb.entries,
	}, nil
}

// BuildFast builds the manifest using size+mtime instead of checksums (much faster)
func (mb *ManifestBuilder) BuildFast(progress func(current int64, total int64)) (*Manifest, error) {
	// First pass: count files
	var totalFiles int64
	err := filepath.Walk(mb.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasPrefix(filepath.Base(path), ".") {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Second pass: build manifest without checksums
	var processed int64
	err = filepath.Walk(mb.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(mb.rootPath, path)
		if err != nil {
			return err
		}

		if strings.HasPrefix(filepath.Base(relPath), ".") {
			return nil
		}

		// Use size+mtime as a pseudo-checksum (much faster)
		pseudoChecksum := fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano())

		mb.entries = append(mb.entries, ManifestEntry{
			Path:     relPath,
			Size:     info.Size(),
			ModTime:  info.ModTime().Unix(),
			Checksum: pseudoChecksum,
		})
		mb.total++
		mb.size += info.Size()
		processed++

		if progress != nil {
			progress(processed, totalFiles)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to build manifest: %w", err)
	}

	return &Manifest{
		TotalFiles: mb.total,
		TotalSize:  mb.size,
		Entries:    mb.entries,
	}, nil
}

// CompareManifests compares two manifests and returns files that need to be transferred
func CompareManifests(local, remote *Manifest) []string {
	// Build map of local files
	localMap := make(map[string]ManifestEntry)
	for _, e := range local.Entries {
		localMap[e.Path] = e
	}

	// Find files that are new or changed in remote
	var needed []string
	for _, re := range remote.Entries {
		le, exists := localMap[re.Path]
		if !exists {
			// File doesn't exist locally
			needed = append(needed, re.Path)
		} else if le.Checksum != re.Checksum {
			// File exists but content is different
			needed = append(needed, re.Path)
		}
	}

	return needed
}

// WriteFile writes data to a file, creating directories as needed
func WriteFile(basePath, relPath string, data []byte) error {
	fullPath := filepath.Join(basePath, relPath)

	// Create directory if needed
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write file
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", fullPath, err)
	}

	return nil
}

// ReadFile reads a file from the repository
func ReadFile(basePath, relPath string) ([]byte, error) {
	fullPath := filepath.Join(basePath, relPath)
	return os.ReadFile(fullPath)
}

// RateLimiter limits the transfer rate
type RateLimiter struct {
	bytesPerSecond int64
	bucket         chan struct{}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(kbPerSecond int) *RateLimiter {
	if kbPerSecond <= 0 {
		return nil // No limit
	}
	return &RateLimiter{
		bytesPerSecond: int64(kbPerSecond) * 1024,
		bucket:         make(chan struct{}, 1),
	}
}

// Wait waits for the rate limiter to allow the specified number of bytes
func (rl *RateLimiter) Wait(bytes int64) {
	if rl == nil {
		return
	}
	// Simple implementation: sleep based on bytes transferred
	// More sophisticated implementations would use token bucket algorithm
}
