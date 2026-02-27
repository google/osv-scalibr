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

package alibabaaccesskey_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/alibabaaccesskey"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	testAccessID = `LTAI5tHSr51ziCnfuHvwdeDw`
	testSecret   = `nyK2q4hL34mCKaEvElY253q1yAF0FL`
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		alibabaaccesskey.NewDetector(),
		fmt.Sprintf("%s:%s", testAccessID, testSecret),
		alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
	)
}

// TestDetector_truePositives tests for cases where we know the Detector
// will successfully find and pair Alibaba Cloud credentials.
func TestDetector_truePositives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{alibabaaccesskey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "simple matching string no space",
			input: fmt.Sprintf("%s:%s", testAccessID, testSecret),
			want: []veles.Secret{
				alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
			},
		},
		{
			name: "alibaba credentials config format",
			input: fmt.Sprintf(`[default]
aliyun_access_key_id = %s
aliyun_access_key_secret = %s`, testAccessID, testSecret),
			want: []veles.Secret{
				alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
			},
		},
		{
			name: "json formatted credentials",
			input: fmt.Sprintf(`{
				"access_id": "%s",
				"secret": "%s"
			}`, testAccessID, testSecret),
			want: []veles.Secret{
				alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
			},
		},
		{
			name: "valid formats mixed with invalid noise",
			input: fmt.Sprintf(`
valid_id: %s
invalid_id: WRONGtHSr51ziCnfuHvwdeDw
valid_secret: %s
invalid_secret: WRONG-InvalidSecret123456789012`, testAccessID, testSecret),
			want: []veles.Secret{
				alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
			},
		},
		{
			name: "multiple distinct matches",
			// Using a slightly altered second ID/Secret to test multiple extractions
			input: fmt.Sprintf(`
config_app1:
%s
%s

config_app2:
LTAI5tFmcWVFFahTdzmBnvdz
bUSdD6sqU249iGR3wUcYHOtpOVQG8y`, testAccessID, testSecret),
			want: []veles.Secret{
				alibabaaccesskey.Credentials{AccessID: testAccessID, Secret: testSecret},
				alibabaaccesskey.Credentials{AccessID: "LTAI5tFmcWVFFahTdzmBnvdz", Secret: "bUSdD6sqU249iGR3wUcYHOtpOVQG8y"},
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
// should NOT find a valid pair of Alibaba Cloud credentials.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{alibabaaccesskey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	// Notice how we don't need to specify "want" here.
	// The struct defaults to nil for the slice, which is exactly what we expect!
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
			name:  "invalid access id format - wrong prefix",
			input: fmt.Sprintf("WRONGtHSr51ziCnfuHvwdeDw:%s", testSecret),
		},
		{
			name:  "invalid secret format - too short",
			input: fmt.Sprintf("%s:nyK2q4hL34mCKaEvElY253", testAccessID),
		},
		{
			name:  "access ID present but no secret",
			input: fmt.Sprintf("app_id: %s", testAccessID),
		},
		{
			name:  "secret present but no access ID",
			input: fmt.Sprintf("app_secret: %s", testSecret),
		},
		{
			name: "access ID and secret are too far apart (exceeds 200 chars)",
			input: fmt.Sprintf("config_app1:\n%s", testAccessID) +
				strings.Repeat("\nfiller line with random data", 10) +
				fmt.Sprintf("\nconfig_app2:\n%s", testSecret),
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
