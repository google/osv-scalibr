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

package bitbucket_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/bitbucket"
)

const (
	testURL = `https://user:password@bitbucket.org/workspace/project-repo.git`
	// this is an actual PAT which is no longer valid
	tokenURL = `https://x-token-auth:ATCTT3xFfGN0eyq0kne3JViBVaR5XhmCYI-3P5OwXu82WjbOscjhEeYywA-NfMVGxUd4HPmS93ZWAFoWcmCeiTl017IosZX52yZfmdzIhQ2p5mO69aOIX6lbhNJHnJw7JFd4bGTyw9LQelA3s0XcI78l2DZt13i38gZyARfNxMLY0SOCMbF20bg=DD5CAD63@bitbucket.org/osv-scalibr-test/test.git`
)

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{bitbucket.NewDetector()})
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
				bitbucket.Credentials{FullURL: testURL},
			},
		},
		{
			name:  "token",
			input: tokenURL,
			want: []veles.Secret{
				bitbucket.Credentials{FullURL: tokenURL},
			},
		},
		{
			name: "git_config_file",
			input: `
[remote "origin"]
	url = https://user:password@bitbucket.org/workspace/project-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`,
			want: []veles.Secret{
				bitbucket.Credentials{FullURL: testURL},
			},
		},
		{
			name:  "multiple_distinct_matches",
			input: testURL + "\n" + tokenURL,
			want: []veles.Secret{
				bitbucket.Credentials{FullURL: testURL},
				bitbucket.Credentials{FullURL: tokenURL},
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

func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{bitbucket.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
		},
		{
			name:  "wrong_host",
			input: "https://user:password@github.com/workspace/project.git",
		},
		{
			name:  "not_git_url",
			input: "https://user:password@bitbucket.org/workspace/project",
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
