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

package image

import (
	"errors"
	"testing"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/imagedsl"
)

func TestFindBaseImageIndex(t *testing.T) {
	tests := []struct {
		name      string
		history   string
		wantError error
	}{
		{
			name:      "empty_history",
			history:   ``,
			wantError: ErrBaseImageNotFound,
		},
		{
			name:      "single_empty_history",
			history:   `empty-layer Empty Layer`,
			wantError: ErrBaseImageNotFound,
		},
		{
			name:      "single_non_empty_history",
			history:   `layer Non Empty Layer`,
			wantError: ErrBaseImageNotFound,
		},
		{
			name: "single_CMD_command_in_history",
			history: `
				layer       Non Empty Layer
				empty-layer CMD["somecmd"]
			`,
			wantError: ErrBaseImageNotFound,
		},
		{
			name: "two_CMD_commands_in_history",
			history: `
				layer       ADD file:123 in /
				empty-layer CMD["/bin/sh"]             <-- want
				layer       RUN apt-get update
				layer       COPY dir /dir
				empty-layer ENTRYPOINT ["entrypoint.sh"]
				empty-layer CMD ["buildcmd"]
			`,
		},
		{
			name: "nginx_image_with_multiple_base_images_in_history",
			history: `
				layer       ADD rootfs.tar.xz /
				empty-layer CMD["bash"]                         <-- want
				empty-layer ENV NGINX_VERSION=1.27.2
				layer       RUN /bin/sh -c set -x
				layer       COPY file1 /file1
				empty-layer Entrypoint ["/docker-entrypoint.sh"]
				empty-layer EXPOSE map[80/tcp:{}]
				empty-layer STOPSIGNAL SIGQUIT
				empty-layer CMD ["nginx" "-g" "daemon off;"]
			`,
		},
		{
			name: "custom_nginx_image_with_multiple_base_images_in_history",
			history: `
				layer       ADD rootfs.tar.xz /
				empty-layer CMD["bash"]
				empty-layer ENV NGINX_VERSION=1.27.2
				layer       RUN /bin/sh -c set -x
				layer       COPY file1 /file1
				empty-layer Entrypoint ["/docker-entrypoint.sh"]
				empty-layer EXPOSE map[80/tcp:{}]
				empty-layer STOPSIGNAL SIGQUIT
				empty-layer CMD ["nginx" "-g" "daemon off;"]    <-- want
				layer       /bin/sh -c #(nop) COPY custom-binary /custom-binary
				empty-layer /bin/sh -c #(nop)  CMD ["buildcmd"]
			`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			histories, wantIndex, hasWant := imagedsl.MustParseHistory(t, test.history)
			if test.wantError == nil && !hasWant {
				t.Fatalf("test case %q must mark expected base image layer with `<-- want`", test.name)
			}
			if test.wantError != nil && hasWant {
				t.Fatalf("test case %q expects error %v and must not set `<-- want`", test.name, test.wantError)
			}

			gotIndex, gotErr := findBaseImageIndex(histories)
			if !errors.Is(gotErr, test.wantError) {
				t.Fatalf("findBaseImageIndex() error = %v, want %v", gotErr, test.wantError)
			}
			if gotIndex != wantIndex {
				t.Errorf("findBaseImageIndex() = %d, want %d", gotIndex, wantIndex)
			}
		})
	}
}
