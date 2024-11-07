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

// Package image provides functionality to scan a container image by layers for software
// inventory.
package image

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	// cmdPrefix is the prefix for CMD instructions in the history created by.
	cmdPrefix         = "/bin/sh -c #(nop)  CMD"
	cmdBuildKitPrefix = "CMD"
)

// Originally from https://github.com/aquasecurity/trivy/blob/1f5f34895823fae81bf521fc939bee743a50e304/pkg/fanal/image/image.go#L111
// Modified to return non empty index.
//
// GuessBaseImageIndex tries to guess index of base layer. Index counting only non empty layers.
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd"
//     will be skipped.
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in step 3.
func guessBaseImageIndex(histories []v1.History) int {
	baseImageIndex := -1
	var foundNonEmpty bool
	for i := len(histories) - 1; i >= 0; i-- {
		h := histories[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, cmdPrefix) ||
			strings.HasPrefix(h.CreatedBy, cmdBuildKitPrefix) { // BuildKit
			baseImageIndex = i
			break
		}
	}

	if baseImageIndex == -1 {
		return -1
	}

	// TODO b/378124478 - Using the non-empty index to calculate the base image index doesn't take
	// into account having a series of base images. Figure out if we just want to return
	// baseImageIndex here.
	nonEmptyIndex := 0
	for i := 0; i <= baseImageIndex; i++ {
		if histories[i].EmptyLayer {
			continue
		}
		nonEmptyIndex++
	}
	return nonEmptyIndex
}
