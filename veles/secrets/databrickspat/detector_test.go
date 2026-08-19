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

package databrickspat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/databrickspat"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testPAT = `dapi0123456789abcdef0123456789abcdef`
const testPATWithSuffix = `dapi0123456789abcdef0123456789abcdef-2`

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		databrickspat.NewDetector(),
		testPAT,
		databrickspat.UserAccountPAT{Token: testPAT},
	)
}

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databrickspat.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	otherToken := testPAT[:len(testPAT)-1] + "0"
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: testPAT,
		want: []veles.Secret{
			databrickspat.UserAccountPAT{Token: testPAT},
		},
	}, {
		name:  "optional single digit suffix",
		input: testPATWithSuffix,
		want: []veles.Secret{
			databrickspat.UserAccountPAT{Token: testPATWithSuffix},
		},
	}, {
		name:  "match at end of env assignment",
		input: `DATABRICKS_TOKEN=` + testPAT,
		want: []veles.Secret{
			databrickspat.UserAccountPAT{Token: testPAT},
		},
	}, {
		name:  "multiple distinct matches",
		input: testPAT + "\n" + otherToken,
		want: []veles.Secret{
			databrickspat.UserAccountPAT{Token: testPAT},
			databrickspat.UserAccountPAT{Token: otherToken},
		},
	}, {
		name: "larger input containing token",
		input: fmt.Sprintf(`
	[DEFAULT]
	token = "%s"
		`, testPAT),
		want: []veles.Secret{
			databrickspat.UserAccountPAT{Token: testPAT},
		},
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

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{databrickspat.NewDetector()})
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
		name:  "short token should not match",
		input: testPAT[:len(testPAT)-1],
	}, {
		name:  "long token should not match",
		input: testPAT + "0",
	}, {
		name:  "invalid hex character should not match",
		input: testPAT[:len(testPAT)-1] + "g",
	}, {
		name:  "uppercase hex should not match",
		input: strings.ToUpper(testPAT),
	}, {
		name:  "incorrect prefix should not match",
		input: "dapo" + testPAT[len("dapi"):],
	}, {
		name:  "two digit suffix should not match as full token",
		input: testPAT + "-20",
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
