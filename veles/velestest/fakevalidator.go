// Copyright 2026 Google LLC
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

package velestest

import (
	"context"

	"github.com/google/osv-scalibr/veles"
)

var _ veles.Validator[FakeStringSecret] = &FakeValidator[FakeStringSecret]{}

// FakeValidator is a fake veles.Validator for a specific Secret type S.
//
// If Err is non-nil, Validate will always return ValidationStatusFailed
// regardless of the value of Status.
type FakeValidator[S veles.Secret] struct {
	Status veles.ValidationStatus
	Err    error
}

// NewFakeValidator returns a new fake veles.Validator for a specific Secret S.
func NewFakeValidator[S veles.Secret](status veles.ValidationStatus, err error) *FakeValidator[S] {
	return &FakeValidator[S]{
		Status: status,
		Err:    err,
	}
}

// NewFakeStringSecretValidator creates a fake Validator for FakeStringSecrets.
func NewFakeStringSecretValidator(status veles.ValidationStatus, err error) *FakeValidator[FakeStringSecret] {
	return NewFakeValidator[FakeStringSecret](status, err)
}

// NewFakeIntSecretValidator creates a fake Validator for FakeIntSecrets.
func NewFakeIntSecretValidator(status veles.ValidationStatus, err error) *FakeValidator[FakeIntSecret] {
	return NewFakeValidator[FakeIntSecret](status, err)
}

// Validate returns the internal state of the fake while also respecting the
// context.
func (v *FakeValidator[S]) Validate(ctx context.Context, s S) (veles.ValidationStatus, error) {
	if err := ctx.Err(); err != nil {
		return veles.ValidationFailed, err
	}
	if err := v.Err; err != nil {
		return veles.ValidationFailed, err
	}
	return v.Status, nil
}
