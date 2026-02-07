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

package codecommit_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecommit"
)

const (
	testURL        = `https://user:pat@git-codecommit.us-east-1.amazonaws.com/v1/repos/osv-scalibr-test`
	anotherTestURL = `https://another:pat@git-codecommit.eu-west-1.amazonaws.com/v1/repos/osv-scalibr-test`
)

func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{codecommit.NewDetector()})
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
				codecommit.Credentials{FullURL: testURL},
			},
		},
		{
			name: "git_config_file",
			input: `
[remote "origin"]
	url = https://user:pat@git-codecommit.us-east-1.amazonaws.com/v1/repos/osv-scalibr-test
	fetch = +refs/heads/*:refs/remotes/origin/*
`,
			want: []veles.Secret{
				codecommit.Credentials{FullURL: testURL},
			},
		},
		{
			name:  "multiple_distinct_matches",
			input: testURL + "\n" + anotherTestURL,
			want: []veles.Secret{
				codecommit.Credentials{FullURL: testURL},
				codecommit.Credentials{FullURL: anotherTestURL},
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
	engine, err := veles.NewDetectionEngine([]veles.Detector{codecommit.NewDetector()})
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
