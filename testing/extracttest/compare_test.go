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

package extracttest

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestPackageCmpLess(t *testing.T) {
	type args struct {
		a *extractor.Package
		b *extractor.Package
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Location difference",
			args: args{
				a: &extractor.Package{
					Name:      "a",
					Version:   "2.0.0",
					Locations: []string{"aaa/bbb"},
				},
				b: &extractor.Package{
					Name:      "a",
					Version:   "1.0.0",
					Locations: []string{"ccc/ddd"},
				},
			},
			want: true,
		},
		{
			name: "Version difference",
			args: args{
				a: &extractor.Package{
					Name:      "a",
					Version:   "2.0.0",
					Locations: []string{"aaa/bbb"},
				},
				b: &extractor.Package{
					Name:      "a",
					Version:   "1.0.0",
					Locations: []string{"aaa/bbb"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PackageCmpLess(tt.args.a, tt.args.b); got != tt.want {
				t.Errorf("PackageCmpLess() = %v, want %v", got, tt.want)
			}
		})
	}
}
