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

package anthropicapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testKey  = "sk-ant-api03-test123456789012345678901234567890123456789012345678"
	adminKey = "sk-ant-admin01-test123456789012345678901234567890123456789012345678"
)

func TestDetectorAcceptance(t *testing.T) {
	d := anthropicapikey.NewDetector()
	cases := []struct {
		name   string
		input  string
		secret veles.Secret
	}{
		{
			name:   "model-key",
			input:  testKey,
			secret: anthropicapikey.ModelAPIKey{Key: testKey},
		},
		{
			name:   "workspace-key",
			input:  adminKey,
			secret: anthropicapikey.WorkspaceAPIKey{Key: adminKey},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			velestest.AcceptDetector(t, d, tc.input, tc.secret)
		})
	}
}

func TestDetector(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{anthropicapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "model_key",
		input: testKey,
		want: []veles.Secret{
			anthropicapikey.ModelAPIKey{Key: testKey},
		},
	}, {
		name:  "workspace_key",
		input: adminKey,
		want: []veles.Secret{
			anthropicapikey.WorkspaceAPIKey{Key: adminKey},
		},
	}, {
		name:  "multiple_keys",
		input: testKey + " " + adminKey,
		want: []veles.Secret{
			anthropicapikey.ModelAPIKey{Key: testKey},
			anthropicapikey.WorkspaceAPIKey{Key: adminKey},
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

func TestDetector_NoMatches(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{anthropicapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
	}{{
		name:  "empty_input",
		input: "",
	}, {
		name:  "wrong_prefix",
		input: "sk-openai-api03-test123",
	}, {
		name:  "too_short",
		input: "sk-ant-api03",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() found %d secrets, want 0", len(got))
			}
		})
	}
}
