// Copyright 2024 Google LLC
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

package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestGuessBaseImageIndex(t *testing.T) {
	tests := []struct {
		name      string
		histories []v1.History
		wantIndex int
	}{
		{
			name:      "empty history",
			histories: []v1.History{},
			wantIndex: -1,
		},
		{
			name: "single empty history",
			histories: []v1.History{
				{
					CreatedBy:  "Empty Layer",
					EmptyLayer: true,
				},
			},
			wantIndex: -1,
		},
		{
			name: "single non empty history",
			histories: []v1.History{
				{
					CreatedBy:  "Non Empty Layer",
					EmptyLayer: false,
				},
			},
			wantIndex: -1,
		},
		{
			name: "single CMD command in history",
			histories: []v1.History{
				{
					CreatedBy:  "Non Empty Layer",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "CMD[\"somecmd\"]",
					EmptyLayer: true,
				},
			},
			wantIndex: -1,
		},
		{
			name: "two CMD commands in history",
			histories: []v1.History{
				{
					CreatedBy:  "ADD file:123 in /",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "CMD[\"/bin/sh\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "RUN apt-get update",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "COPY mysecret /",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "ENTRYPOINT [\"entrypoint.sh\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "CMD [\"somecmd\"]",
					EmptyLayer: true,
				},
			},
			wantIndex: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotIndex := guessBaseImageIndex(test.histories)
			if gotIndex != test.wantIndex {
				t.Errorf("guessBaseImageIndex(%v) = %v, want: %v", test.histories, gotIndex, test.wantIndex)
			}
		})
	}
}
