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

package secrets_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher/secrets"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

type testEnricherSubCase struct {
	name  string
	input inventory.Inventory
	want  inventory.Inventory
}

func TestEnricher(t *testing.T) {
	errTest := errors.New("some validation error")
	path := "/foo/bar/key.json"
	cases := []struct {
		name   string
		engine *veles.ValidationEngine
		subs   []testEnricherSubCase
	}{
		{
			name:   "only strings supported",
			engine: veles.NewValidationEngine(veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil))),
			subs: []testEnricherSubCase{
				{
					name: "supported",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeStringSecret("FOO"),
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeStringSecret("FOO"),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationValid,
								},
							},
						},
					},
				},
				{
					name: "unsupported",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationUnsupported,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "per_secret_errors",
			engine: veles.NewValidationEngine(
				veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)),
				veles.WithValidator(velestest.NewFakeIntSecretValidator(veles.ValidationFailed, errTest)),
			),
			subs: []testEnricherSubCase{
				{
					name: "single_error",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationFailed,
									Err:    errTest,
								},
							},
						},
					},
				},
				{
					name: "multiple_errors",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
							},
							{
								Secret:   velestest.NewFakeIntSecret(456),
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationFailed,
									Err:    errTest,
								},
							},
							{
								Secret:   velestest.NewFakeIntSecret(456),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationFailed,
									Err:    errTest,
								},
							},
						},
					},
				},
				{
					name: "mixed",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
							},
							{
								Secret:   velestest.NewFakeStringSecret("foo"),
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   velestest.NewFakeIntSecret(123),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationFailed,
									Err:    errTest,
								},
							},
							{
								Secret:   velestest.NewFakeStringSecret("foo"),
								Location: path,
								Validation: inventory.SecretValidationResult{
									Status: veles.ValidationValid,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enricher := secrets.NewWithEngine(tc.engine)
			for _, sc := range tc.subs {
				t.Run(sc.name, func(t *testing.T) {
					if err := enricher.Enrich(t.Context(), nil, &sc.input); err != nil {
						t.Errorf("Enrich() error: %v, want nil", err)
					}
					got := &sc.input
					want := &sc.want
					// We can rely on the order of Secrets in the inventory here, since the enricher is not supposed to change it.
					if diff := cmp.Diff(want, got, cmpopts.EquateErrors(), cmpopts.IgnoreTypes(time.Time{})); diff != "" {
						t.Errorf("Enrich() got diff (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestEnricher_respectsContext(t *testing.T) {
	enricher := secrets.NewWithEngine(veles.NewValidationEngine(
		veles.WithValidator(velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)),
	))
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{
			{
				Secret:   velestest.NewFakeStringSecret("foo"),
				Location: "/foo/bar/baz.json",
			},
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := enricher.Enrich(ctx, nil, inv); !errors.Is(err, context.Canceled) {
		t.Errorf("enricher.Enrich() error = nil, want context cancelled")
	}
}

func TestAddValidator(t *testing.T) {
	secret := inventory.Secret{
		Secret:   velestest.NewFakeStringSecret("foo"),
		Location: "/foo/bar/baz.json",
	}
	inv := inventory.Inventory{Secrets: []*inventory.Secret{&secret}}
	enricher := secrets.NewWithEngine(veles.NewValidationEngine()).(*secrets.Enricher)

	// Ensure that it's unsupported.
	if err := enricher.Enrich(t.Context(), nil, &inv); err != nil {
		t.Errorf("Enrich() error: %v, want nil", err)
	}
	if got, want := secret.Validation.Status, veles.ValidationUnsupported; got != want {
		t.Errorf("Enrich() validation status = %q, want %q", got, want)
	}

	// Add new validator and ensure that we now get the correct result.
	if present := secrets.AddValidator(enricher, velestest.NewFakeStringSecretValidator(veles.ValidationValid, nil)); present {
		t.Errorf("AddValidator() = %t, want false", present)
	}
	if err := enricher.Enrich(t.Context(), nil, &inv); err != nil {
		t.Errorf("Enrich() error: %v, want nil", err)
	}
	if got, want := secret.Validation.Status, veles.ValidationValid; got != want {
		t.Errorf("Enrich() validation status = %q, want %q", got, want)
	}
}
