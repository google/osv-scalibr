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

package mongodbatlasrefreshtoken_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/mongodbatlasrefreshtoken"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testRefreshToken = "ZkHO9xXUOXx_A6gAJyqQZX5EJZUTG5c75tAkwd22als"

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		mongodbatlasrefreshtoken.NewDetector(),
		"refresh_token = '"+testRefreshToken+"'",
		mongodbatlasrefreshtoken.MongoDBAtlasRefreshToken{Token: testRefreshToken},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find a MongoDB Atlas Refresh Token/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodbatlasrefreshtoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "refresh_token with equals sign",
			input: `refresh_token = '` + testRefreshToken + `'`,
			want: []veles.Secret{
				mongodbatlasrefreshtoken.MongoDBAtlasRefreshToken{Token: testRefreshToken},
			},
		},
		{
			name:  "refresh_token with colon (YAML style)",
			input: `refresh_token: ` + testRefreshToken,
			want: []veles.Secret{
				mongodbatlasrefreshtoken.MongoDBAtlasRefreshToken{Token: testRefreshToken},
			},
		},
		{
			name:  "refresh_token with double quotes",
			input: `refresh_token = "` + testRefreshToken + `"`,
			want: []veles.Secret{
				mongodbatlasrefreshtoken.MongoDBAtlasRefreshToken{Token: testRefreshToken},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty(), cmpopts.SortSlices(func(a, b veles.Secret) bool {
				return fmt.Sprintf("%v", a) < fmt.Sprintf("%v", b)
			})); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find a MongoDB Atlas Refresh Token.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{mongodbatlasrefreshtoken.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "refresh token without context keyword",
			input: testRefreshToken,
		},
		{
			name:  "malformed assignment - no separator",
			input: `refresh_token` + testRefreshToken,
		},
		{
			name:  "short refresh token should not match",
			input: `refresh_token = 'abc123'`,
		},
	}
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
