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

package gitlabpat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
)

const (
	testKeyVersioned             = "glpat-bzox79Of-KE9FD2LjoXXF4CvyxA.01.0r0l8l6ir"
	testKeyVersionedInvalidCrc32 = "glpat-bzox79Of-KE9FD2LjoXXF4CvyxA.01.0r03gxo7a"
	testKeyRoutable              = "glpat-bzox79Of-KE9FD2LjoXXF4CvyxA.0r03gxo7s"
	testKeyLegacy                = "glpat-vzDNJu3Lvh4YCCekKsnx"
)

// TestDetector_truePositives tests cases where the Detector should find a GitLab PAT.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gitlabpat.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "routable versioned simple",
			input: testKeyVersioned,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
			},
		},
		{
			name:  "routable simple",
			input: testKeyRoutable,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyRoutable},
			},
		},
		{
			name:  "Legacy simple",
			input: testKeyLegacy,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyLegacy},
			},
		},
		{
			name:  "match in middle of string (versioned)",
			input: `GITLAB_PAT="` + testKeyVersioned + `"`,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
			},
		},
		{
			name:  "multiple matches (same token repeated)",
			input: testKeyVersioned + " " + testKeyVersioned + " " + testKeyVersioned,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
			},
		},
		{
			name:  "multiple distinct matches",
			input: testKeyVersioned + "\n" + testKeyRoutable + "\n" + testKeyLegacy,
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
				gitlabpat.GitlabPAT{Pat: testKeyRoutable},
				gitlabpat.GitlabPAT{Pat: testKeyLegacy},
			},
		},
		{
			name:  "multiple distinct matches with extra dot",
			input: testKeyVersioned + ".11aa" + "\n" + testKeyRoutable + ".11aa" + "\n" + testKeyLegacy + ".11aa",
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
				gitlabpat.GitlabPAT{Pat: testKeyRoutable},
				gitlabpat.GitlabPAT{Pat: testKeyLegacy},
			},
		},
		{
			name: "larger input containing versioned key",
			input: fmt.Sprintf(`
		:test_api_key: pat-test
		:gitlab_pat: %s
				`, testKeyVersioned),
			want: []veles.Secret{
				gitlabpat.GitlabPAT{Pat: testKeyVersioned},
			},
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

// TestDetector_trueNegatives tests cases where the Detector should NOT find a GitLab PAT.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gitlabpat.NewDetector()})
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
			name:  "short versioned key should not match",
			input: testKeyVersioned[:len(testKeyLegacy)-10],
		},
		{
			name:  "invalid character in key should not match",
			input: `glpat-` + strings.Repeat("a", 10) + "!" + "aaaa",
		},
		{
			name:  "incorrect prefix should not match",
			input: `glpaa-` + strings.Repeat("a", 51),
		},
		{
			name:  "prefix missing dash should not match",
			input: `glpat` + strings.Repeat("a", 51),
		},
		{
			name:  "invalid CRC32 should not match",
			input: testKeyVersionedInvalidCrc32,
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
