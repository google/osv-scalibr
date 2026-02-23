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

// Package dockerhubpat contains a Veles Secret type and a Detector for
// Docker Hub Personal Access Tokens (prefix `dckr_pat_`).
package dockerhubpat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

// maxTokenLength is the maximum size of a Docker Hub API key.
const maxTokenLength = 36

// patRe is a regular expression that matches a Docker Hub API key.
// Docker Hub Personal Access Tokens have the form: `dckr_pat_` followed by 27
// alphanumeric characters.
var patRe = regexp.MustCompile(`dckr_pat_[A-Za-z0-9_-]{27}`)

var (
	// usernamePattern matches:
	//
	// - `docker login -u/--username` followed by an username
	// - an username key (with or without quotes) followed by an username
	//
	// The username can be with or without quotes
	usernamePattern = regexp.MustCompile(`(?:docker login[^\n]*?(?:-u|--username)(?:\s+|=)|(?i:username)["']?\s*[=:]\s*)["']?([^"'\s]+)`)
)

// NewDetector returns a new Detector that matches
// Docker Hub Personal Access Tokens.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: 100, MaxDistance: 100,
		FindA: pair.FindAllMatches(patRe),
		FindB: findUsernameMatches(),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return DockerHubPAT{Pat: string(p.A.Value), Username: string(p.B.Value)}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return nil, false
			}
			return DockerHubPAT{Pat: string(p.A.Value)}, true
		},
	}
}

func findUsernameMatches() func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		res := []*pair.Match{}
		matches := usernamePattern.FindAllSubmatchIndex(data, -1)
		for _, m := range matches {
			res = append(res, &pair.Match{
				Start: m[0],
				Value: data[m[2]:m[3]],
			})
		}
		return res
	}
}
