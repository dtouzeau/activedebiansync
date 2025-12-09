package webconsole

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var embeddedAssets embed.FS

// GetEmbeddedAssetsFS returns the embedded assets filesystem
func GetEmbeddedAssetsFS() (http.FileSystem, error) {
	subFS, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		return nil, err
	}
	return http.FS(subFS), nil
}

// HasEmbeddedAssets returns true if embedded assets are available
func HasEmbeddedAssets() bool {
	entries, err := embeddedAssets.ReadDir("assets")
	return err == nil && len(entries) > 0
}
