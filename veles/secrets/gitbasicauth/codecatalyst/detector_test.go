// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package codecatalyst_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecatalyst"
)

const (
	testURL    = `https://user:password@git.region.codecatalyst.aws/v1/space/project/repo`
	anotherURL = `https://another:acsp03irh932r4@git.region.codecatalyst.aws/v1/space2/project/test-repo`
)

// TestDetector_truePositives tests for cases where we know the Detector
// will find CodeCatalyst credentials.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{codecatalyst.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple_matching_string",
			input: testURL,
			want: []veles.Secret{
				codecatalyst.Credentials{FullURL: testURL},
			},
		},
		{
			name: "git_config",
			input: `
			[core]
				repositoryformatversion = 0
				filemode = true
				bare = false
				logallrefupdates = true
				ignorecase = true
				precomposeunicode = true
[remote "origin"]
				url = https://user:password@git.region.codecatalyst.aws/v1/space/project/repo
				fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
				remote = origin
				merge = refs/heads/main
`,
			want: []veles.Secret{
				codecatalyst.Credentials{FullURL: testURL},
			},
		},
		{
			name:  "multiple_distinct_matches",
			input: testURL + "\n" + anotherURL,
			want: []veles.Secret{
				codecatalyst.Credentials{FullURL: testURL},
				codecatalyst.Credentials{FullURL: anotherURL},
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find CodeCatalyst credentials.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{codecatalyst.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "bad_host_name",
		input: "https://user:password@github.com/project/repo",
	}, {
		name:  "not_git_url",
		input: `https://another:acsp03irh932r4@region.codecatalyst.aws/v1/space2/project/test-repo`,
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
