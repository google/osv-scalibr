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

package veles_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

type testValidationEngineSubCase struct {
	name  string
	input veles.Secret
	want  veles.ValidationStatus
}

func TestValidationEngine(t *testing.T) {
	cases := []struct {
		name   string
		engine *veles.ValidationEngine
		sub    []testValidationEngineSubCase
	}{
		{
			name:   "empty engine",
			engine: veles.NewValidationEngine(),
			sub: []testValidationEngineSubCase{
				{
					name:  "string unsupported",
					input: velestest.NewFakeStringSecret("foo"),
					want:  veles.ValidationUnsupported,
				},
				{
					name:  "int unsupported",
					input: velestest.NewFakeIntSecret(123),
					want:  veles.ValidationUnsupported,
				},
			},
		},
		{
			name:   "single validator",
			engine: veles.NewValidationEngine(veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil))),
			sub: []testValidationEngineSubCase{
				{
					name:  "supported",
					input: velestest.NewFakeStringSecret("foo"),
					want:  veles.ValidationValid,
				},
				{
					name:  "unsupported",
					input: velestest.NewFakeIntSecret(123),
					want:  veles.ValidationUnsupported,
				},
			},
		},
		{
			name: "multiple validators",
			engine: veles.NewValidationEngine(
				veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)),
				veles.WithValidator(velestest.NewFakeIntSecretValidator(veles.ValidationInvalid, nil)),
			),
			sub: []testValidationEngineSubCase{
				{
					name:  "string supported",
					input: velestest.NewFakeStringSecret("foo"),
					want:  veles.ValidationValid,
				},
				{
					name:  "int supported",
					input: velestest.NewFakeIntSecret(123),
					want:  veles.ValidationInvalid,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, sc := range tc.sub {
				t.Run(sc.name, func(t *testing.T) {
					t.Parallel()
					got, err := tc.engine.Validate(t.Context(), sc.input)
					if err != nil {
						t.Errorf("Validate() error: %v, want nil", err)
					}
					if got != sc.want {
						t.Errorf("Validate() = %q, want %q", got, sc.want)
					}
				})
			}
		})
	}
}

func TestValidationEngine_respectsContext(t *testing.T) {
	engine := veles.NewValidationEngine()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	status, err := engine.Validate(ctx, velestest.NewFakeStringSecret("foo"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Validate() error: %v, want context.Canceled", err)
	}
	if status != veles.ValidationFailed {
		t.Errorf("Validate() = %q, want %q", status, veles.ValidationFailed)
	}
}

func TestValidationEngine_errors(t *testing.T) {
	errTest := errors.New("some error")
	cases := []struct {
		name   string
		engine *veles.ValidationEngine
		input  veles.Secret
	}{
		{
			name: "validation error",
			engine: veles.NewValidationEngine(
				veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationFailed, errTest)),
			),
			input: velestest.NewFakeStringSecret("foo"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, err := tc.engine.Validate(t.Context(), tc.input)
			if !errors.Is(err, errTest) {
				t.Errorf("Validate() error: %v, want %v", err, errTest)
			}
			if status != veles.ValidationFailed {
				t.Errorf("Validate() = %q, want %q", status, veles.ValidationFailed)
			}
		})
	}
}

func TestAddValidator(t *testing.T) {
	validator := velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)
	cases := []struct {
		name        string
		engine      *veles.ValidationEngine
		wantPresent bool
	}{
		{
			name:        "not present",
			engine:      veles.NewValidationEngine(),
			wantPresent: false,
		},
		{
			name: "present",
			engine: veles.NewValidationEngine(
				veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationInvalid, nil)),
			),
			wantPresent: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, want := veles.AddValidator(tc.engine, validator), tc.wantPresent; got != want {
				t.Errorf("AddValidator() = %t, want %t", got, want)
			}
			status, err := tc.engine.Validate(t.Context(), velestest.NewFakeStringSecret("foo"))
			if err != nil {
				t.Errorf("Validate() error: %v, want nil", err)
			}
			if got, want := status, veles.ValidationValid; got != want {
				t.Errorf("Validate() = %q, want %q", got, want)
			}
		})
	}
}
