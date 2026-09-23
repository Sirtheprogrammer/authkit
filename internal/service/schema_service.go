package service

import (
	"fmt"

	"authkit/internal/config"
	"authkit/internal/domain"
)

// SchemaService validates dynamic user schema attributes
type SchemaService struct {
	schema *domain.CustomSchema
}

// NewSchemaService creates a schema service from configuration
func NewSchemaService(cfg config.SchemaConfig) *SchemaService {
	return &SchemaService{
		schema: domain.NewCustomSchema(cfg.Strict, cfg.Fields),
	}
}

// ValidateUserData validates metadata map according to custom schema constraints
func (s *SchemaService) ValidateUserData(metadata map[string]interface{}, isSignup bool) (map[string]interface{}, error) {
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
	return s.schema
}
