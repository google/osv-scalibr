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

package salesforceoauth2refresh_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2refresh"
	"github.com/google/osv-scalibr/veles/velestest"
)

const (
	validClientID = "3MVG123456789.ABCDEF.ABC11112222223456789ABC123456789ABC1"
	validSecret   = "A123456789ABCDEFABC1234567895123456789ABCDEFABC1234567895"
	validRefresh  = "123456789ABCDEFABC1234567895123459876ABCDEFABC1234567895"
)

func TestDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		salesforceoauth2refresh.NewDetector(),
		validClientID+"\n"+"client_secret:"+validSecret+"\n"+"refresh_token:"+validRefresh,
		salesforceoauth2refresh.Credentials{ID: validClientID, Secret: validSecret, Refresh: validRefresh},
	)
}

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{salesforceoauth2refresh.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		// --- Empty or invalid input ---
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "non-credential input",
			input: "Some random text",
			want:  nil,
		},
		{
			name:  "invalid client ID format - wrong prefix",
			input: "3MG123456789.AB_CDEF.ABC123456789ABC123456789ABC12",
			want:  nil,
		},
		{
			name:  "invalid client secret format - underscore",
			input: "123456789ABCDEF123456789ABCDEF1234567_89ABCDEFabcde",
			want:  nil,
		},
		{
			name:  "invalid refresh token format - underscore",
			input: "123456789ABCDEF123456789ABCDEF1234567_89ABCDEFabcde",
			want:  nil,
		},
		{
			name:  "invalid client secret format - too short",
			input: "A123B123-short",
			want:  nil,
		},
		// --- Only client ID or Secret or refresh token ---
		{
			name:  "client ID but no client secret and refresh token",
			input: `app_id: 3MVG123456789.AB_CDEF.ABC123456789`,
			want:  nil,
		},
		{
			name:  "client secret but no client ID and refresh token",
			input: `client_secret: 123456789ABCDEFABC1234567895`,
			want:  nil,
		},
		{
			name:  "refresh token but no client ID and client secret",
			input: `refresh_token: 123456789ABCDEFABC1234567895`,
			want:  nil,
		},
		// -- Single Client ID, Secret and URL in close proximity (happy path) ---
		{
			name: "client_ID_client_secret_and_refresh_token_in_close_proximity",
			input: `3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1
client_secret: 123456789ABCDEFABC1234567895123456789ABCDEFABC1234567895
refresh_token: 123456789ABCDEFCCC1234567895123456789ABCDEFABC1234567895
`,
			want: []veles.Secret{
				salesforceoauth2refresh.Credentials{
					ID:      "3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1",
					Secret:  "123456789ABCDEFABC1234567895123456789ABCDEFABC1234567895",
					Refresh: "123456789ABCDEFCCC1234567895123456789ABCDEFABC1234567895",
				},
			},
		},
		{
			name: "client_secret_in_with_invalid_format",
			input: `3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1
abcdef-1mVwFTjGIXgs2BC2uHzksQi0HAK1`,
			want: nil,
		},
		{
			name: "valid_formats_mixed_with_invalid",
			input: `valid_id: 3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1
invalid_id: 3MG123456789.AB_CDEF.ABC123456789ABC123456789ABC11
client_secret: 12345678901234567123456789012345671234567890123456712345678901234567
client_secret: 1234567890-1234567123456789012345671234567890123456712345678901234567
refresh_token: 12345678901234567123456789032145671234567890123456712345678901234567
refresh_token: 123456789012345671234567890-12345671234567890123456712345678901234567`,
			want: []veles.Secret{
				salesforceoauth2refresh.Credentials{
					ID:      "3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1",
					Secret:  "12345678901234567123456789012345671234567890123456712345678901234567",
					Refresh: "12345678901234567123456789032145671234567890123456712345678901234567",
				},
			},
		},
		// -- Multiple Client ID and Secret in close proximity ---
		{
			name: "complex_file_with_multiple_client_ID_client_secret_and_URL_-_test_proximity",
			input: `
config_app1:
3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1
client_secret: 12345678901234567123456789012345671234567890123456712345678901234567
refresh_token: 12345678901234567123654789012345671234567890123456712345678901234567

config_app2:
3MVG123456789.AB_CEEF.ABC123456789ABC123456789ABC1
client_secret: 12345678901234867123456789012345671234567890123456
refresh_token: 12345678901234867123456987012345671234567890123456`,
			want: []veles.Secret{
				salesforceoauth2refresh.Credentials{
					ID:      "3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1",
					Secret:  "12345678901234567123456789012345671234567890123456712345678901234567",
					Refresh: "12345678901234567123654789012345671234567890123456712345678901234567",
				},
				salesforceoauth2refresh.Credentials{
					ID:      "3MVG123456789.AB_CEEF.ABC123456789ABC123456789ABC1",
					Secret:  "12345678901234867123456789012345671234567890123456",
					Refresh: "12345678901234867123456987012345671234567890123456",
				},
			},
		},
	}

	for _, tc := range tests {
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
