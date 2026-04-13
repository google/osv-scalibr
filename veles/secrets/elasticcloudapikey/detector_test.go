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

package elasticcloudapikey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/elasticcloudapikey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const testKey = "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4="

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		elasticcloudapikey.NewDetector(),
		testKey,
		elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		velestest.WithBackToBack(),
		velestest.WithPad('a'),
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will find an Elastic Cloud API key/s.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{elasticcloudapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{{
		name:  "simple_matching_string",
		input: testKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		},
	}, {
		name:  "match_at_end_of_string",
		input: `ELASTIC_CLOUD_API_KEY=` + testKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		},
	}, {
		name:  "match_in_middle_of_string",
		input: `ELASTIC_CLOUD_API_KEY="` + testKey + `"`,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		},
	}, {
		name:  "multiple_matches",
		input: testKey + testKey + testKey,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		},
	}, {
		name:  "valid_key_with_single_padding",
		input: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAAN5Zs4A=",
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAAN5Zs4A="},
		},
	}, {
		name:  "valid_key_92_chars_no_padding",
		input: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4A",
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4A"},
		},
	}, {
		name:  "multiple_distinct_matches",
		input: testKey + "\n" + "essu_QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC",
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
			elasticcloudapikey.ElasticCloudAPIKey{Key: "essu_QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"},
		},
	}, {
		name: "larger_input_containing_key",
		input: fmt.Sprintf(`
:test_api_key: elastic-test
:ELASTIC_CLOUD_API_KEY: %s
		`, testKey),
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
		},
	}, {
		name:  "potential_match_longer_than_max_key_length",
		input: testKey + `extra`,
		want: []veles.Secret{
			elasticcloudapikey.ElasticCloudAPIKey{Key: testKey},
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

// TestDetector_trueNegatives tests for cases where we know the Detector
// will not find an Elastic Cloud API key.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{elasticcloudapikey.NewDetector()})
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
		name:  "short_key_should_not_match",
		input: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09",
	}, {
		name:  "invalid_character_in_key_should_not_match",
		input: "essu_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAA@#$%^&*",
	}, {
		name:  "incorrect_prefix_should_not_match",
		input: "esss_VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4=",
	}, {
		name:  "prefix_missing_should_not_match",
		input: "VWtSQlNXNWFjMEpWWVZsbFVUZDBORmRQTldJNmNuWnVYMU5yY1ZGdlJ6aHVlRE5rWmxGelIyUk9kdz09AAAAANx5Zs4=",
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
