package domain

import (
	"testing"
)

func TestCustomSchemaValidation(t *testing.T) {
	minLen := 3
	maxLen := 20
	minVal := 18.0

	schema := NewCustomSchema(true, []FieldDefinition{
		{
			Name:      "username",
			Type:      FieldTypeString,
			Required:  true,
			MinLength: &minLen,
			MaxLength: &maxLen,
		},
		{
			Name:     "age",
			Type:     FieldTypeNumber,
			Required: false,
			Min:      &minVal,
		},
		{
			Name:          "tier",
			Type:          FieldTypeString,
			AllowedValues: []interface{}{"free", "pro", "enterprise"},
			Default:       "free",
		},
	})

	// Valid data
	validData := map[string]interface{}{
		"username": "alexm",
		"age":      25,
		"tier":     "pro",
	}

	result, err := schema.Validate(validData, true)
	if err != nil {
		t.Fatalf("Validation failed for valid data: %v", err)
	}

	if result["tier"] != "pro" {
		t.Fatalf("Expected tier pro, got %v", result["tier"])
	}

	// Missing required field on signup
	invalidData := map[string]interface{}{
		"age": 25,
	}
	_, err = schema.Validate(invalidData, true)
	if err == nil {
		t.Fatalf("Expected error for missing required field, got nil")
	}

	// Default value applied
	dataWithDefaults := map[string]interface{}{
		"username": "johndoe",
	}
	res2, err := schema.Validate(dataWithDefaults, true)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if res2["tier"] != "free" {
		t.Fatalf("Expected default value 'free', got %v", res2["tier"])
	}

	// Strict mode rejection of undeclared field
	dataWithExtra := map[string]interface{}{
		"username": "johndoe",
		"hacker":   true,
	}
	_, err = schema.Validate(dataWithExtra, true)
	if err == nil {
		t.Fatalf("Expected error for undeclared field in strict mode, got nil")
	}
}
