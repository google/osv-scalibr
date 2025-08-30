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

package grokxaiapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	grokxaiapikey "github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
)

const (
	// Example valid API and Management keys.
	detectorAPIKey  = "xai-lY6JXMlP8jvE3CAgqkn2EiRlMZ444mzFQS0JLKIv4p6ZcoGGxW2Mk6EIMs72dLXylw0Kg4MLyOHGDj6c"
	detectorMgmtKey = "xai-token-jS4Ke7pHhyiPVH0gWNcFmpnBLAMRgZchGWroIOWqLK5TB2obw8zbgVudrULg5DkZNdOoKsQ6rema3LGz"
)

// TestAPIKeyDetector_truePositives tests that the API key detector finds xai-... keys.
func TestAPIKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{grokxaiapikey.NewAPIKeyDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorAPIKey,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
		},
	}, {
		name:  "match at end of string",
		input: `XAI_KEY=` + detectorAPIKey,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
		},
	}, {
		name:  "match in quotes",
		input: `env "XAI"="` + detectorAPIKey + `"`,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
		},
	}, {
		name:  "multiple matches",
		input: detectorAPIKey + detectorAPIKey,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
		},
	}, {
		name:  "larger input containing key",
		input: fmt.Sprintf("some: yaml\napi_key: %s\nother: value\n", detectorAPIKey),
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
		},
	}, {
		name:  "potential match longer than max key length",
		input: detectorAPIKey + "EXTRA",
		want: []veles.Secret{
			grokxaiapikey.GrokXAIAPIKey{Key: detectorAPIKey},
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

// TestAPIKeyDetector_trueNegatives tests that non-matching inputs do not produce false positives.
func TestAPIKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{grokxaiapikey.NewAPIKeyDetector()})
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
		input: detectorAPIKey[:len(detectorAPIKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: "xai-" + strings.ReplaceAll(detectorAPIKey[4:], "A", "-"),
	}, {
		name:  "incorrect prefix should not match",
		input: "XAi-" + detectorAPIKey[4:],
	}, {
		name:  "prefix missing dash should not match",
		input: "xaix" + detectorAPIKey[3:],
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

// TestManagementKeyDetector_truePositives tests that the management key detector finds xai-token-... keys.
func TestManagementKeyDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{grokxaiapikey.NewManagementKeyDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple matching string",
		input: detectorMgmtKey,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey},
		},
	}, {
		name:  "match at end of string",
		input: `GROK_MGMT=` + detectorMgmtKey,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey},
		},
	}, {
		name:  "match in quotes",
		input: `secret="` + detectorMgmtKey + `"`,
		want: []veles.Secret{
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey},
		},
	}, {
		name:  "multiple distinct matches",
		input: detectorMgmtKey + "\n" + detectorMgmtKey[:len(detectorMgmtKey)-1] + "1\n",
		want: []veles.Secret{
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey},
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey[:len(detectorMgmtKey)-1] + "1"},
		},
	}, {
		name:  "larger input containing key",
		input: fmt.Sprintf("config:\n  management_key: %s\n", detectorMgmtKey),
		want: []veles.Secret{
			grokxaiapikey.GrokXAIManagementKey{Key: detectorMgmtKey},
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

// TestManagementKeyDetector_trueNegatives tests negative cases for the management key detector.
func TestManagementKeyDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{grokxaiapikey.NewManagementKeyDetector()})
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
		input: detectorMgmtKey[:len(detectorMgmtKey)-1],
	}, {
		name:  "invalid character in key should not match",
		input: "xai-token-" + strings.ReplaceAll(detectorMgmtKey[len("xai-token-"):], "o", "-"),
	}, {
		name:  "incorrect prefix should not match",
		input: "xaitoken-" + detectorMgmtKey[len("xai-token-"):],
	}, {
		name:  "prefix missing dash should not match",
		input: "xaitoken" + detectorMgmtKey[len("xai-token-")-1:],
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
