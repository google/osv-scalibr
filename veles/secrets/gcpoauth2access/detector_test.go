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

package gcpoauth2access_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2access"
)

const (
	realToken  = "ya29.a0AQQ_BDQWmhK2ywGDxkB2uBTykNRPd89V28-MUwZnVWZl3AMP1BD5s2UiIEdFNThSh-etTblBm6BPd0K1JmuRiyTNW_ICOa3-3gkS2SHoaNgm4x-jPEeDLsFa5ppHPurdNxRU_H9PnfpKCU-3ayKluSVmdQqXUYpo1PwqqbnGw0FWUEL2uZgS8GZ1lL7_9zSrt36PdCYaCgYKAcQSAQ8SFQHGX2MiS2cGUcQliabDBsSTYb8iTw0206"
	shortToken = "ya29.a0AQQ_BDQWmhK2ywGDxkB2uBTykNRPd89V28"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpoauth2access.NewDetector()})
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
			name:  "token too short",
			input: "ya29.a0AQQ",
			want:  nil,
		},
		// --- Valid tokens ---
		{
			name:  "real example token",
			input: realToken,
			want:  []veles.Secret{gcpoauth2access.Token{Token: realToken}},
		},
		{
			name:  "short token",
			input: shortToken,
			want:  []veles.Secret{gcpoauth2access.Token{Token: shortToken}},
		},
		{
			name: "token in json",
			input: fmt.Sprintf(`{
				"some_key": "some_value",
				"access_token": %q,
				"expires_in": 3920,
				"other_key": "other_value",
			}`, realToken),
			want: []veles.Secret{gcpoauth2access.Token{Token: realToken}},
		},
		{
			name:  "token in json",
			input: "Authorization: Bearer " + realToken,
			want:  []veles.Secret{gcpoauth2access.Token{Token: realToken}},
		},
		{
			name:  "multiple tokens",
			input: "start, " + realToken + strings.Repeat(", some other data\n", 100) + shortToken + ", end",
			want: []veles.Secret{
				gcpoauth2access.Token{Token: realToken},
				gcpoauth2access.Token{Token: shortToken},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Detect(%q) returned unexpected diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}
