// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package veles

import (
	"context"
	"fmt"
	"reflect"
)

// ValidationStatus represents the result status of validating a Secret using a
// corresponding Validator.
type ValidationStatus string

const (
	// ValidationUnspecified is the default value for ValidationStatus. It should
	// not be returned by a concrete Validator.
	//
	// The value of ValidationUnspecified is the empty string instead of a
	// meaningful value so it is the automatic default.
	ValidationUnspecified ValidationStatus = ""
	// ValidationUnsupported occurs only if a ValidationEngine has no Validator
	// for a given Secret type.
	ValidationUnsupported ValidationStatus = "VALIDATION_UNSUPPORTED"
	// ValidationFailed occurs if a Validator was not able to make a validation
	// decision because an error occurred.
	// This will be returned alongside the error so calling code can decide
	// whether it's worth retrying.
	ValidationFailed ValidationStatus = "VALIDATION_FAILED"
	// ValidationInvalid occurs if a validation was successful but the result is
	// negative: the Secret is not valid.
	ValidationInvalid ValidationStatus = "VALIDATION_INVALID"
	// ValidationValid occurs if the validation was successful and the result is
	// positive: the Secret is valid.
	ValidationValid ValidationStatus = "VALIDATION_VALID"
)

// Validator is a Validator for the concrete Secret type S.
//
// It is used to validate Secrets of type S and returns the corresponding
// ValidationStatus or an error (in which case the ValidationStatus is
// ValidationStatusFailed).
type Validator[S Secret] interface {
	Validate(ctx context.Context, secret S) (ValidationStatus, error)
}

// ValidationEngine bundles a number of Validators together.
//
// There can only be one Validator[S] for each concrete S.
type ValidationEngine struct {
	vs map[reflect.Type]GenericValidator
}

// ValidationEngineOption is an option that can be used to configure a
// ValidationEngine at creation via NewValidationEngine.
type ValidationEngineOption func(*ValidationEngine)

// WithValidator configures the ValidationEngine to use the provided Validator.
//
// This will fail if a Validator for the given Secret Type S has already been
// registered with the ValidationEngine.
func WithValidator[S Secret](v Validator[S]) ValidationEngineOption {
	return func(e *ValidationEngine) {
		AddValidator(e, v)
	}
}

// WithGenericValidator configures the ValidationEngine to use the provided
// type-erased GenericValidator with the secret type explicitly specified.
func WithGenericValidator(v GenericValidator, typ reflect.Type) ValidationEngineOption {
	return func(e *ValidationEngine) {
		AddGenericValidator(e, v, typ)
	}
}

// NewValidationEngine creates a new ValidationEngine that bundles a number of
// Validators together.
//
// Validators are provided via the WithValidator ValidationEngineOption.
//
// Returns an error if no Validators are provided or if there are multiple
// Validators for the same Secret type.
func NewValidationEngine(opts ...ValidationEngineOption) *ValidationEngine {
	e := &ValidationEngine{
		vs: make(map[reflect.Type]GenericValidator),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// AddValidator adds a new Validator for a concrete Secret type S to the engine.
//
// Returns whether there was already a Validator in place that now got replaced.
func AddValidator[S Secret](e *ValidationEngine, v Validator[S]) bool {
	typ := reflect.TypeFor[S]()
	return AddGenericValidator(e, &wrapped[S]{v: v}, typ)
}

// AddGenericValidator adds a new GenericValidator for a concrete Secret type typ to the engine.
//
// Returns whether there was already a GenericValidator in place that now got replaced.
func AddGenericValidator(e *ValidationEngine, v GenericValidator, typ reflect.Type) bool {
	_, replaced := e.vs[typ]
	e.vs[typ] = v
	return replaced
}

// Validate validates a given Secret using one of the configured Validators.
//
// If no Validator for the Secret's type is configured, it will return a result
// with Status ValidationUnsupported. This is not an error because some Secrets
// might just not have corresponding Validators.
//
// An error is returned if something went wrong during validation, e.g.
// connection issues or timeouts. In that case ValidationStatus will be
// ValidationStatusFailed.
func (e *ValidationEngine) Validate(ctx context.Context, s Secret) (ValidationStatus, error) {
	if err := ctx.Err(); err != nil {
		return ValidationFailed, err
	}
	v, present := e.vs[reflect.TypeOf(s)]
	if !present {
		return ValidationUnsupported, nil
	}
	return v.Validate(ctx, s)
}

// GenericValidator is used to type erase type-erase Validator[S] using a shared interface.
type GenericValidator interface {
	Validate(ctx context.Context, s Secret) (ValidationStatus, error)
}

// NewGenericValidator wraps a specific validator around a type-erased one.
func NewGenericValidator[S Secret](v Validator[S]) GenericValidator {
	return &wrapped[S]{v: v}
}

type wrapped[S Secret] struct {
	v Validator[S]
}

func (w wrapped[S]) Validate(ctx context.Context, s Secret) (ValidationStatus, error) {
	t, ok := s.(S)
	if !ok {
		// The engine makes sure that this should never happen!
		return ValidationFailed, fmt.Errorf("unexpected Secret of type %T, want %T", s, t)
	}
	return w.v.Validate(ctx, t)
}
