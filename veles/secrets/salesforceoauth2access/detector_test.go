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

package salesforceoauth2access_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2access"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{salesforceoauth2access.NewDetector()})
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
			name:  "non-token input",
			input: "Some random text",
			want:  nil,
		},
		{
			name:  "invalid token format - wrong prefix",
			input: "00B123456789!AB_CDEF.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC12",
			want:  nil,
		},
		{
			name:  "invalid token format - underscore in organizationID",
			input: "00D1234567-89!AB_CDEF.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC12",
			want:  nil,
		},
		{
			name:  "invalid token format - too short",
			input: "00D123456789!AB_CDEF",
			want:  nil,
		},
		// -- Multiple Tokens in close proximity ---
		{
			name: "complex_file_with_multiple_Tokens_-_test_proximity",
			input: `
config_app1:
00D123456789!AB_CDEF.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC12

config_app2:
00D123456789!AB_CDBB.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC13
			`,
			want: []veles.Secret{
				salesforceoauth2access.Token{
					Token:  "00D123456789!AB_CDEF.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC12",
				},
				salesforceoauth2access.Token{
					Token:  "00D123456789!AB_CDBB.ABC123456789ABC123456789ABC12ABC123456789ABC123456789ABC13",
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
