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

package samreg

import (
	"strings"
	"testing"
)

func TestUserFEnabled(t *testing.T) {
	tests := []struct {
		name        string
		buffer      []byte
		wantEnabled bool
		wantErr     bool
	}{
		{
			name:        "user_is_enabled_returns_true",
			buffer:      []byte(strings.Repeat("A", 56) + "\x00"),
			wantEnabled: true,
		},
		{
			name:        "user_is_disabled_returns_false",
			buffer:      []byte(strings.Repeat("A", 56) + "\x01"),
			wantEnabled: false,
		},
		{
			name:    "userF_structure_parsing_error_returns_error",
			buffer:  []byte(""),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userF := newUserF(tc.buffer, "irrelevant")
			got, gotErr := userF.Enabled()

			if (gotErr != nil) != tc.wantErr {
				t.Errorf("Enabled(): unexpected error: %v", gotErr)
			}

			if tc.wantErr {
				return
			}

			if got != tc.wantEnabled {
				t.Errorf("Enabled(): got %v, want %v", got, tc.wantEnabled)
			}
		})
	}
}
