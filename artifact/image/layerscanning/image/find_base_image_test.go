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

func TestFindBaseImageIndex(t *testing.T) {
	tests := []struct {
		name      string
		histories []v1.History
		wantIndex int
		wantError error
	}{
		{
			name:      "empty history",
			histories: []v1.History{},
			wantError: ErrBaseImageNotFound,
		},
		{
			name: "single empty history",
			histories: []v1.History{
				{
					CreatedBy:  "Empty Layer",
					EmptyLayer: true,
				},
			},
			wantError: ErrBaseImageNotFound,
		},
		{
			name: "single non empty history",
			histories: []v1.History{
				{
					CreatedBy:  "Non Empty Layer",
					EmptyLayer: false,
				},
			},
			wantError: ErrBaseImageNotFound,
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
			wantError: ErrBaseImageNotFound,
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
					CreatedBy:  "COPY dir /dir",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "ENTRYPOINT [\"entrypoint.sh\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "CMD [\"buildcmd\"]",
					EmptyLayer: true,
				},
			},
			wantIndex: 1,
		},
		{
			name: "nginx image with multiple base images in history",
			histories: []v1.History{
				{
					CreatedBy:  "ADD rootfs.tar.xz /",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "CMD[\"bash\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "ENV NGINX_VERSION=1.27.2",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "RUN /bin/sh -c set -x",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "COPY file1 /file1",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "Entrypoint [\"/docker-entrypoint.sh\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "EXPOSE map[80/tcp:{}]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "STOPSIGNAL SIGQUIT",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "CMD [\"nginx\" \"-g\" \"daemon off;\"]",
					EmptyLayer: true,
				},
			},
			// Want to return the index of the following command: CMD ["bash"]
			wantIndex: 1,
		},
		{
			name: "custom nginx image with multiple base images in history",
			histories: []v1.History{
				{
					CreatedBy:  "ADD rootfs.tar.xz /",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "CMD[\"bash\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "ENV NGINX_VERSION=1.27.2",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "RUN /bin/sh -c set -x",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "COPY file1 /file1",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "Entrypoint [\"/docker-entrypoint.sh\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "EXPOSE map[80/tcp:{}]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "STOPSIGNAL SIGQUIT",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "CMD [\"nginx\" \"-g\" \"daemon off;\"]",
					EmptyLayer: true,
				},
				{
					CreatedBy:  "/bin/sh -c #(nop) COPY custom-binary /custom-binary",
					EmptyLayer: false,
				},
				{
					CreatedBy:  "/bin/sh -c #(nop)  CMD [\"buildcmd\"]",
					EmptyLayer: true,
				},
			},
			// Want to return the index of the following command: CMD ["nginx" "-g" "daemon off;"]
			wantIndex: 8,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotIndex, gotErr := findBaseImageIndex(test.histories)
			if test.wantError != gotErr {
				t.Errorf("findBaseImageIndex(%v) returned error: %v, want error: %v", test.histories, gotErr, test.wantError)
				return
			}

			if gotIndex != test.wantIndex {
				t.Errorf("guessBaseImageIndex(%v) = %v, want: %v", test.histories, gotIndex, test.wantIndex)
			}
		})
	}
}
