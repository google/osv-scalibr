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

package pypiapitoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/pypiapitoken"
)

const testKey = `pypi-AgEIc433aS5vcmcffDgyZDA0MzFkLWMzZjEtNDlhNy1iOWQwLfflMjE5NmNkMjhjNQACKlszLCI22UBiYzQ2Yi05YjNhhTQ5NmItYWIxMHYhMGI3MmEyOWI5MzYiXQAABiCJBI80LFFz0JvS6UIj2LzgV9N-BQnBAD2123Dyu9xs33`

// TestDetector_truePositives tests for cases where we know the Detector
// will find a PyPI API Token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pypiapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testKey,
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
		},
	}, {
		name:  "match at end of string",
		input: `PYPI_API_TOKEN=` + testKey,
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
		},
	}, {
		name:  "match in middle of string",
		input: `PYPI_API_TOKEN="` + testKey + `"`,
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + "\n" + testKey + "\n" + testKey,
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
			pypiapitoken.PyPIAPIToken{Token: testKey},
			pypiapitoken.PyPIAPIToken{Token: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
			pypiapitoken.PyPIAPIToken{Token: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: PYPI-test
:PYPI_API_TOKEN: %s
		`, testKey),
		want: []veles.Secret{
			pypiapitoken.PyPIAPIToken{Token: testKey},
		},
	},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			fmt.Printf("got = %+v\n", got)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a PyPI API Token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{pypiapitoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty input",
		input: "",
	}, {
		name:  "short key should not match",
		input: testKey[:len(testKey)-90],
	}, {
		name:  "invalid character(!) in key should not match",
		input: `pypi-AgEIc433aS5vcmcffDgyZDA0!MzFkLWMzZjEtNDlhNy1iOWQwLfflMjE5NmNkMjhjNQACKlszLCI22UBiYzQ2Yi05Yj`,
	}, {
		name:  "incorrect prefix should not match",
		input: `pV1-MzFkLWMzZjEtNDlhNy1iOWQwLfflMjE5NmNkMjhjNQACKlszLCI22UBiYzQ2Yi05Yj`,
	}, {
		name:  "prefix missing dash should not match",
		input: `MzFkLWMzZjEtNDlhNy1iOWQwLfflMjE5NmNkMjhjNQACKlszLCI22UBiYzQ2Yi05Yj`,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
