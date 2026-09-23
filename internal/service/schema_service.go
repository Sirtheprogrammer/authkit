package service

import (
	"fmt"
	"sync"

	"authkit/internal/config"
	"authkit/internal/domain"
)

// SchemaService validates dynamic user schema attributes
type SchemaService struct {
	mu     sync.RWMutex
	schema *domain.CustomSchema
}

// NewSchemaService creates a schema service from configuration
func NewSchemaService(cfg config.SchemaConfig) *SchemaService {
	return &SchemaService{
		schema: domain.NewCustomSchema(cfg.Strict, cfg.Fields),
	}
}

// UpdateSchema hot-reloads the active schema constraints at runtime
func (s *SchemaService) UpdateSchema(cfg config.SchemaConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schema = domain.NewCustomSchema(cfg.Strict, cfg.Fields)
}

// ValidateUserData validates metadata map according to custom schema constraints
func (s *SchemaService) ValidateUserData(metadata map[string]interface{}, isSignup bool) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.schema == nil {
		if metadata == nil {
			return make(map[string]interface{}), nil
		}
		return metadata, nil
	}
	validated, err := s.schema.Validate(metadata, isSignup)
	if err != nil {
		return nil, fmt.Errorf("schema validation error: %w", err)
	}
	return validated, nil
}

// GetSchema returns the current schema configuration
func (s *SchemaService) GetSchema() *domain.CustomSchema {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.schema
}
