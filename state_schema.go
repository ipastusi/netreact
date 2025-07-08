package main

import (
	_ "embed"
	"github.com/kaptinlin/jsonschema"
)

//go:embed state_schema.json
var rawSchema []byte

func validateState(state []byte) []error {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(rawSchema)
	if err != nil {
		return []error{err}
	}

	var errors []error
	result := schema.Validate(state)
	if !result.IsValid() {
		for _, err = range result.Errors {
			errors = append(errors, err)
		}
	}
	return errors
}
