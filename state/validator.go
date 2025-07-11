package state

import (
	_ "embed"
	"github.com/kaptinlin/jsonschema"
)

//go:embed schema.json
var rawSchema []byte

func ValidateState(stateBytes []byte) []error {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(rawSchema)
	if err != nil {
		return []error{err}
	}

	var errors []error
	result := schema.Validate(stateBytes)
	if !result.IsValid() {
		for _, err = range result.Errors {
			errors = append(errors, err)
		}
	}
	return errors
}
