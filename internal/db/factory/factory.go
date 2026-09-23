package factory

import (
	"context"
	"fmt"
	"strings"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/db/mongodb"
	"authkit/internal/db/mysql"
	"authkit/internal/db/postgres"
	"authkit/internal/db/sqlite"
)

// NewDatabase initializes and connects to the configured storage engine
func NewDatabase(ctx context.Context, cfg config.DatabaseConfig) (db.Database, error) {
	dbType := strings.ToLower(strings.TrimSpace(cfg.Type))

	// Auto-detect type if not explicitly set
	if dbType == "" {
		if strings.HasPrefix(cfg.URL, "postgres://") || strings.HasPrefix(cfg.URL, "postgresql://") {
			dbType = "postgres"
		} else if strings.HasPrefix(cfg.URL, "mongodb://") || strings.HasPrefix(cfg.URL, "mongodb+srv://") {
			dbType = "mongodb"
		} else if strings.Contains(cfg.URL, "@tcp(") {
			dbType = "mysql"
		} else {
			dbType = "sqlite"
		}
	}

	var d db.Database

	switch dbType {
	case "sqlite", "sqlite3":
		fp := cfg.Filepath
		if fp == "" && cfg.URL != "" {
			fp = cfg.URL
		}
		if fp == "" {
			fp = "./authkit.db"
		}
		d = sqlite.New(fp)

	case "postgres", "postgresql":
		d = postgres.New(cfg)

	case "mysql":
		d = mysql.New(cfg)

	case "mongodb", "mongo":
		d = mongodb.New(cfg)

	default:
		return nil, fmt.Errorf("unsupported database type: '%s'. Supported: sqlite, postgres, mysql, mongodb", dbType)
	}

	if err := d.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", dbType, err)
	}

	if err := d.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("failed to run %s migrations: %w", dbType, err)
	}

	return d, nil
}
