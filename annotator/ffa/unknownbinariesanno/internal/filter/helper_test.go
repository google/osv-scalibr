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

package filter_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
)

func TestAttributePackage(t *testing.T) {
	tests := []struct {
		name       string
		initialSet map[string]*extractor.Package
		path       string
		wantSet    map[string]*extractor.Package
	}{
		{
			name: "Normal case",
			initialSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{},
					},
				},
			},
			path: "usr/bin/ls",
			wantSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{
							LocalFilesystem: true,
						},
					},
				},
			},
		},
		{
			name: "Path with leading slash",
			initialSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{},
					},
				},
			},
			path: "/usr/bin/ls",
			wantSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{
							LocalFilesystem: true,
						},
					},
				},
			},
		},
		{
			name: "Wrong metadata type",
			initialSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: "not a UnknownBinaryMetadata type",
				},
			},
			path: "usr/bin/ls",
			wantSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: "not a UnknownBinaryMetadata type",
				},
			},
		},
		{
			name: "File not found in set",
			initialSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{
							LocalFilesystem: false,
						},
					},
				},
			},
			path: "usr/bin/notexist",
			wantSet: map[string]*extractor.Package{
				"usr/bin/ls": {
					Metadata: &unknownbinariesextr.UnknownBinaryMetadata{
						Attribution: unknownbinariesextr.Attribution{
							LocalFilesystem: false,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter.AttributePackage(tt.initialSet, tt.path)
			if diff := cmp.Diff(tt.wantSet, tt.initialSet); diff != "" {
				t.Errorf("AttributePackage() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
