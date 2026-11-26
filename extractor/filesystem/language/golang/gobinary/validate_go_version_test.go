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

import "testing"

func TestValidateGoVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "release version",
			version: "go1.26.1",
			want:    "1.26.1",
		},
		{
			name:    "linux experiment suffix",
			version: "go1.26.1-X:nodwarf5",
			want:    "1.26.1",
		},
		{
			name:    "darwin experiment suffix",
			version: "go1.26.1-X:loopvar",
			want:    "1.26.1",
		},
		{
			name:    "multiple experiment suffixes",
			version: "go1.26.1-X:nodwarf5,loopvar",
			want:    "1.26.1",
		},
		{
			name:    "prerelease with experiment suffix",
			version: "go1.27rc1-X:loopvar",
			want:    "1.27rc1",
		},
		{
			name:    "space separated development version",
			version: "go1.20-pre3 +a813be86df",
			want:    "1.20-pre3",
		},
		{
			name:    "space separated experiment suffix",
			version: "devel go1.27-abc123 X:loopvar",
			want:    "devel",
		},
		{
			name:    "empty version",
			version: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateGoVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateGoVersion(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validateGoVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}
