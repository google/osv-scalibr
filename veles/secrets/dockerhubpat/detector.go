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

// Package dockerhubpat contains a Veles Secret type and a Detector for
// Docker Hub Personal Access Tokens (prefix `dckr_pat_`).
package dockerhubpat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// maxTokenLength is the maximum size of a Docker Hub API key.
const maxTokenLength = 36

// patRe is a regular expression that matches a Docker Hub API key.
// Docker Hub Personal Access Tokens have the form: `dckr_pat_` followed by 27
// alphanumeric characters.
var patRe = regexp.MustCompile(`dckr_pat_[A-Za-z0-9-_-]{27}`)

// dockerLoginCmdRe is a regular expression that matches a Docker Hub API key with an email or username used in switches of docker login command.
// for example, `docker login -u username -p dckr_pat_{27}`.
var dockerLoginCmdRe = regexp.MustCompile(`docker\s+login\s+(?:(?:(?:-u|--username)[=\s]+(\S+))|(?:(?:-p|--password)[=\s]+(dckr_pat_[a-zA-Z0-9_-]{27})))\s+(?:(?:(?:-u|--username)[=\s]+(\S+))|(?:(?:-p|--password)[=\s]+(dckr_pat_[a-zA-Z0-9_-]{27})))`)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a new Detector that matches
// Docker Hub Personal Access Tokens.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var offsets []int

	// 1. docker login command username and pat detection
	dockerLoginCmdMatches := dockerLoginCmdRe.FindAllSubmatchIndex(content, -1)
	for _, m := range dockerLoginCmdMatches {
		if m[2] != -1 && m[8] != -1 {
			secrets = append(secrets, DockerHubPAT{Username: string(content[m[2]:m[3]]), Pat: string(content[m[8]:m[9]])})
			offsets = append(offsets, m[8])
		}
		if m[6] != -1 && m[4] != -1 {
			secrets = append(secrets, DockerHubPAT{Username: string(content[m[6]:m[7]]), Pat: string(content[m[4]:m[5]])})
			offsets = append(offsets, m[4])
		}
	}

	// 2. only pat detection, don't add duplicates from the docker login command
	patReMatches := patRe.FindAllIndex(content, -1)
	for _, m := range patReMatches {
		newPat := string(content[m[0]:m[1]])
		isDuplicate := false
		// Check if this PAT already exists in the secret slice and mapped to an username
		for _, existingSecret := range secrets {
			if dhPat, ok := existingSecret.(DockerHubPAT); ok {
				if dhPat.Username != "" && dhPat.Pat == newPat {
					isDuplicate = true
					break
				}
			}
		}
		// Only add if not a duplicate
		if !isDuplicate {
			secrets = append(secrets, DockerHubPAT{Username: "", Pat: newPat})
			offsets = append(offsets, m[0])
		}
	}

	return secrets, offsets
}
