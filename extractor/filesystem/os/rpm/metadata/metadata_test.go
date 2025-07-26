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

package metadata_test

import (
	"testing"

	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
)

func TestToNamespace(t *testing.T) {
	tests := []struct {
		osID          string
		wantNamespace string
	}{
		{
			osID:          "centos",
			wantNamespace: "centos",
		},
		{
			osID:          "fedora",
			wantNamespace: "fedora",
		},
		{
			osID:          "amzn",
			wantNamespace: "amazon",
		},
		{
			osID:          "",
			wantNamespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.osID, func(t *testing.T) {
			metadata := rpmmeta.Metadata{
				OSID: tt.osID,
			}
			ns := metadata.ToNamespace()
			if ns != tt.wantNamespace {
				t.Fatalf("ToNamespace(%s): got %v, want %v", tt.osID, ns, tt.wantNamespace)
			}
		})
	}
}
