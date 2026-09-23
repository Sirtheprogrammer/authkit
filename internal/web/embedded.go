package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFS embed.FS

// GetStaticFS returns the sub-filesystem rooted at "static"
func GetStaticFS() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}
