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

package gobinary

import (
	"testing"
)

func TestValidateGoVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "empty version",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "standard release version",
			input:   "go1.26.1",
			want:    "1.26.1",
			wantErr: false,
		},
		{
			name:    "standard release version without patch",
			input:   "go1.24",
			want:    "1.24",
			wantErr: false,
		},
		{
			name:    "version with development commit hash",
			input:   "go1.20-pre3 +a813be86df",
			want:    "1.20-pre3",
			wantErr: false,
		},
		{
			name:    "version with single experiment suffix",
			input:   "go1.26.1-X:nodwarf5",
			want:    "1.26.1",
			wantErr: false,
		},
		{
			name:    "version with another experiment suffix",
			input:   "go1.26.1-X:loopvar",
			want:    "1.26.1",
			wantErr: false,
		},
		{
			name:    "version with multiple experiments in suffix",
			input:   "go1.26.1-X:fieldtrack,nodwarf5",
			want:    "1.26.1",
			wantErr: false,
		},
		{
			name:    "prerelease version with experiment suffix",
			input:   "go1.20rc1-X:nodwarf5",
			want:    "1.20rc1",
			wantErr: false,
		},
		{
			name:    "version with experiment suffix and development commit metadata",
			input:   "go1.26.1-X:nodwarf5 +a813be86df",
			want:    "1.26.1",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateGoVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateGoVersion(%q) returned err: %v, wantErr: %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validateGoVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
