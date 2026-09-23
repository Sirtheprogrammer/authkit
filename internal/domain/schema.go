package domain

import (
	"fmt"
	"regexp"
)

// FieldType defines the data type of a custom schema field
type FieldType string

const (
	FieldTypeString  FieldType = "string"
	FieldTypeNumber  FieldType = "number"
	FieldTypeBoolean FieldType = "boolean"
	FieldTypeArray   FieldType = "array"
	FieldTypeObject  FieldType = "object"
)

// FieldDefinition specifies constraints for a custom user schema field
type FieldDefinition struct {
	Name          string        `json:"name" yaml:"name"`
	Type          FieldType     `json:"type" yaml:"type"`
	Required      bool          `json:"required" yaml:"required"`
	MinLength     *int          `json:"min_length,omitempty" yaml:"min_length,omitempty"`
	MaxLength     *int          `json:"max_length,omitempty" yaml:"max_length,omitempty"`
	Min           *float64      `json:"min,omitempty" yaml:"min,omitempty"`
	Max           *float64      `json:"max,omitempty" yaml:"max,omitempty"`
	Pattern       string        `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty" yaml:"allowed_values,omitempty"`
	Default       interface{}   `json:"default,omitempty" yaml:"default,omitempty"`
	Description   string        `json:"description,omitempty" yaml:"description,omitempty"`
}

// CustomSchema manages dynamic fields configuration and validation
type CustomSchema struct {
	Strict bool                       `json:"strict" yaml:"strict"` // if true, rejects undeclared fields
	Fields map[string]FieldDefinition `json:"fields" yaml:"fields"`
}

// NewCustomSchema creates a new schema with given fields
func NewCustomSchema(strict bool, fields []FieldDefinition) *CustomSchema {
	fieldMap := make(map[string]FieldDefinition)
	for _, f := range fields {
		fieldMap[f.Name] = f
	}
	return &CustomSchema{
		Strict: strict,
		Fields: fieldMap,
	}
}

// Validate checks given metadata against the schema rules
func (cs *CustomSchema) Validate(metadata map[string]interface{}, isSignup bool) (map[string]interface{}, error) {
	if cs == nil || (len(cs.Fields) == 0 && !cs.Strict) {
		if metadata == nil {
			return make(map[string]interface{}), nil
		}
		return metadata, nil
	}

	result := make(map[string]interface{})
	if metadata != nil {
		for k, v := range metadata {
			result[k] = v
		}
	}

	// 1. Check for unexpected fields if strict mode is enabled
	if cs.Strict {
		for k := range result {
			if _, exists := cs.Fields[k]; !exists {
				return nil, fmt.Errorf("field '%s' is not permitted in custom schema", k)
			}
		}
	}

	// 2. Validate declared fields and apply defaults
	for name, def := range cs.Fields {
		val, exists := result[name]

		// Apply default value if missing
		if !exists || val == nil {
			if def.Default != nil {
				result[name] = def.Default
				val = def.Default
				exists = true
			}
		}

		// Check required constraints
		if (!exists || val == nil || val == "") && def.Required && isSignup {
			return nil, fmt.Errorf("custom field '%s' is required", name)
		}

		if !exists || val == nil {
			continue
		}

		// Type and constraint validation
		if err := validateFieldValue(def, val); err != nil {
			return nil, fmt.Errorf("custom field '%s' invalid: %w", name, err)
		}
	}

	return result, nil
}

func validateFieldValue(def FieldDefinition, val interface{}) error {
	switch def.Type {
	case FieldTypeString:
		strVal, ok := val.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", val)
		}
		if def.MinLength != nil && len(strVal) < *def.MinLength {
			return fmt.Errorf("minimum length is %d, got %d", *def.MinLength, len(strVal))
		}
		if def.MaxLength != nil && len(strVal) > *def.MaxLength {
			return fmt.Errorf("maximum length is %d, got %d", *def.MaxLength, len(strVal))
		}
		if def.Pattern != "" {
			matched, err := regexp.MatchString(def.Pattern, strVal)
			if err != nil || !matched {
				return fmt.Errorf("value does not match pattern '%s'", def.Pattern)
			}
		}
	case FieldTypeNumber:
		var num float64
		switch n := val.(type) {
		case float64:
			num = n
		case float32:
			num = float64(n)
		case int:
			num = float64(n)
		case int64:
			num = float64(n)
		default:
			return fmt.Errorf("expected number, got %T", val)
		}
		if def.Min != nil && num < *def.Min {
			return fmt.Errorf("minimum value is %f, got %f", *def.Min, num)
		}
		if def.Max != nil && num > *def.Max {
			return fmt.Errorf("maximum value is %f, got %f", *def.Max, num)
		}
	case FieldTypeBoolean:
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", val)
		}
	case FieldTypeArray:
		switch val.(type) {
		case []interface{}, []string, []int:
			// valid array
		default:
			return fmt.Errorf("expected array, got %T", val)
		}
	case FieldTypeObject:
		if _, ok := val.(map[string]interface{}); !ok {
			return fmt.Errorf("expected object, got %T", val)
		}
	}

	// Check allowed values
	if len(def.AllowedValues) > 0 {
		matched := false
		for _, allowed := range def.AllowedValues {
			if fmt.Sprintf("%v", allowed) == fmt.Sprintf("%v", val) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("value '%v' is not in allowed values: %v", val, def.AllowedValues)
		}
	}

	return nil
}
