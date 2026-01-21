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

package bitwardenapikey_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/bitwardenapikey"
)

const (
	testID     = "user.12345678-abcd-1234-abcd-1234567890ab"
	testSecret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{bitwardenapikey.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "valid_pair_in_env_format",
			input: "BW_CLIENTID=" + testID + "\nBW_CLIENTSECRET=" + testSecret,
			want: []veles.Secret{
				bitwardenapikey.BitwardenAPIKey{
					ClientID:     testID,
					ClientSecret: testSecret,
				},
			},
		},
		{
			name:  "valid_pair_in_json_format",
			input: `{"client_id": "` + testID + `", "client_secret": "` + testSecret + `"}`,
			want: []veles.Secret{
				bitwardenapikey.BitwardenAPIKey{
					ClientID:     testID,
					ClientSecret: testSecret,
				},
			},
		},
		{
			name:  "invalid_id_format",
			input: "BW_CLIENTID=wrong." + testID[5:] + "\nBW_CLIENTSECRET=" + testSecret,
			want:  nil,
		},
		{
			name:  "secret_too_short",
			input: "BW_CLIENTID=" + testID + "\nBW_CLIENTSECRET=short",
			want:  nil,
		},
		{
			name: "far_apart_pair",
			input: "BW_CLIENTID=" + testID + strings.Repeat("\nfiller", 200) + "\nBW_CLIENTSECRET=" + testSecret,
			want: nil,
		},
	}

	for _, tc := range tests {
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
