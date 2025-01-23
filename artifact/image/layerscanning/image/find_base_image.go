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

package image

import (
	"errors"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	// cmdPrefix is the prefix for CMD instructions in the history created by.
	cmdPrefix                = "/bin/sh -c #(nop)  CMD"
	cmdBuildKitPrefix        = "CMD"
	entrypointPrefix         = "/bin/sh -c #(nop)  ENTRYPOINT"
	entrypointBuildKitPrefix = "ENTRYPOINT"
)

// ErrBaseImageNotFound is returned when the base image is not found.
var ErrBaseImageNotFound = errors.New("unable to find base image not found")

// findBaseImageIndex tries to determine the index of the base image given the command history of
// the image.
//
// e.g. In the following example, we should detect when the nginx:latest image layers start.
//
//	FROM nginx:latest
//	COPY custom-binary /custom-binary
//	CMD ["buildcmd"]
//
// with the base image (nginx:latest) having the following history:
//
//	ADD rootfs.tar.xz /
//	CMD ["bash"]
//	ENV NGINX_VERSION=1.27.2
//	RUN /bin/sh -c set -x
//	COPY file1 /file1
//	ENTRYPOINT [\"/docker-entrypoint.sh\"]
//	EXPOSE map[80/tcp:{}]
//	STOPSIGNAL SIGQUIT
//	CMD [\"nginx\" \"-g\" \"daemon off;\"]
//
// The complete history of the image would be as follows:
//
//	ADD rootfs.tar.xz /
//	CMD ["bash"]
//	ENV NGINX_VERSION=1.27.2
//	RUN /bin/sh -c set -x
//	COPY file1 /file1
//	ENTRYPOINT [\"/docker-entrypoint.sh\"]
//	EXPOSE map[80/tcp:{}]
//	STOPSIGNAL SIGQUIT
//	CMD [\"nginx\" \"-g\" \"daemon off;\"] // finds the second to last CMD and returns index
//	COPY custom-binary /custom-binary
//	CMD ["buildcmd"] // skips the last CMD
//
// This function tries to the determines that the base image ends at the second to last CMD command.
// It does this by:
//  1. Iterating through the histories starting from the final layer and going backwards.
//  2. Skipping all the empty layers until it finds a populated layer. This includes commands such
//     as ENTRYPOINT, EXPOSE, STOPSIGNAL, CMD, etc.
//  3. Once a populated layer is found, it looks for the first empty layer with a CMD or ENTRYPOINT
//     command.
//  4. If no CMD or ENTRYPOINT command is found, then an error is returned.
func findBaseImageIndex(histories []v1.History) (int, error) {
	// A populated layer refers to a layer that either adds, removes, or modifies files / directories
	// in a container image.
	foundPopulatedLayer := false

	possibleFinalBaseImageCommands := []string{
		cmdPrefix,
		cmdBuildKitPrefix,
		entrypointPrefix,
		entrypointBuildKitPrefix,
	}

	for i := len(histories) - 1; i >= 0; i-- {
		h := histories[i]

		buildCommand := h.CreatedBy
		layerIsEmpty := h.EmptyLayer

		if !foundPopulatedLayer {
			// Skip empty layers if we haven't found a populated layer yet. This includes commands such as
			// ENTRYPOINT, EXPOSE, STOPSIGNAL, CMD, etc.
			if layerIsEmpty {
				continue
			}
			foundPopulatedLayer = true
		}

		// If we've found a populated layer, then we can skip all other populated layers.
		if !layerIsEmpty {
			continue
		}

		// Look for CMD or ENTRYPOINT commands in potential base image.
		for _, prefix := range possibleFinalBaseImageCommands {
			if strings.HasPrefix(buildCommand, prefix) {
				return i, nil
			}
		}
	}
	return 0, ErrBaseImageNotFound
}
