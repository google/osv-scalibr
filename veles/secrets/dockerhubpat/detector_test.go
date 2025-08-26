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

package dockerhubpat_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
)

const testKey = `dckr_pat_7awgM4jG5SQvxcvmNzhKj8PQjxo`

// TestDetector_truePositives tests for cases where we know the Detector
// will find a Docker Hub PAT/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{dockerhubpat.NewDetector()})
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
			dockerhubpat.DockerHubPAT{Pat: testKey},
		},
	}, {
		name:  "match of docker login command 1",
		input: `docker login -u username -p ` + testKey,
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey, Username: "username"},
		},
	}, {
		name:  "match of docker login command 2",
		input: `docker login -p ` + testKey + ` -u username `,
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey, Username: "username"},
		},
	}, {
		name:  "match in middle of string",
		input: `DOCKERHUBPAT="` + testKey + `"`,
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey},
		},
	}, {
		name:  "multiple matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey},
			dockerhubpat.DockerHubPAT{Pat: testKey},
			dockerhubpat.DockerHubPAT{Pat: testKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: testKey + "\n" + testKey[:len(testKey)-1] + "a",
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey},
			dockerhubpat.DockerHubPAT{Pat: testKey[:len(testKey)-1] + "a"},
		},
	}, {
		name: "larger input containing key",
		input: fmt.Sprintf(`
		:test_api_key: pat-test
		:dockerhub_pat: %s
				`, testKey),
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: testKey + `extra`,
		want: []veles.Secret{
			dockerhubpat.DockerHubPAT{Pat: testKey},
		},
	}}
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
// will not find a Docker Hub PAT.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{dockerhubpat.NewDetector()})
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
		input: testKey[:len(testKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: `dckr_pat_7a@wgM4jG5SQvxcvmNzhKj8PQjxoQ`,
	}, {
		name:  "incorrect prefix should not match",
		input: `aaar_pat_7awgM4jG5SQvxcvmNzhKj8PQjxo`,
	}, {
		name:  "prefix missing dash should not match",
		input: `7awgM4jG5SQvxcvmNzhKj8PQjxo`,
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
