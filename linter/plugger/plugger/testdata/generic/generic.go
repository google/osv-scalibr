package generic

import (
	"context"
)

type Validator[S any] interface {
	Validate(ctx context.Context, secret S) (int, error)
}

type TestPointer struct{}

func (t *TestPointer) Validate(ctx context.Context, secret int) (int, error) {
	return 1, nil
}

type Test struct{}

func (t *Test) Validate(ctx context.Context, secret int) (int, error) {
	return 1, nil
}

type TestAnotherType struct{}

func (t *TestAnotherType) Validate(ctx context.Context, secret string) (int, error) {
	return 1, nil
}

// ---

type IComplex[T any, S comparable] interface {
	Test(S) T
}

type Complex struct{}

func (a Complex) Test(s int) bool {
	return false
}

type Random struct{}

func (r Random) Random(s int) bool {
	return false
}

type MoreRandom struct{}

func (r MoreRandom) Random() bool {
	return false
}
