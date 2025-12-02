package generic

import "context"

// Validator is a validator interface
type Validator[S any] interface {
	Validate(ctx context.Context, secret S) (int, error)
}

// GenericValidator is a generic validator
type GenericValidator[T any] struct{}

// Validate implements Validator.
func (v *GenericValidator[T]) Validate(ctx context.Context, secret T) (int, error) {
	panic("unimplemented")
}

// NewValidator returns an integer validator
func NewValidator() *GenericValidator[int] {
	return &GenericValidator[int]{}
}
