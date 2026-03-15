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

package gitlab

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	_ veles.Detector = NewRunnerAuthTokenDetector()
)

const (
	maxRunnerTokenLength    = 100
	maxRunnerHostnameLength = 253
	maxRunnerDistance       = 200
)

var (
	runnerTokenRe    = regexp.MustCompile(`\bglrt-[A-Za-z0-9_-]{20,}(?:\.[0-9]{2}\.[A-Za-z0-9_-]+)?\b`)
	runnerHostnameRe = regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9.]*(?::[0-9]+)?)`)
)

// NewRunnerAuthTokenDetector returns a new Detector that matches
// GitLab Runner authentication tokens.
func NewRunnerAuthTokenDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxRunnerTokenLength, maxRunnerHostnameLength),
		MaxDistance:   maxRunnerDistance,
		FindA:         pair.FindAllMatches(runnerTokenRe),
		FindB:         findRunnerHostnameMatches(),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return RunnerAuthToken{
				Token:    string(p.A.Value),
				Hostname: string(p.B.Value),
			}, true
		},
		FromPartialPair: func(p pair.Pair) (veles.Secret, bool) {
			if p.A == nil {
				return nil, false
			}
			return RunnerAuthToken{Token: string(p.A.Value)}, true
		},
	}
}

func findRunnerHostnameMatches() func(data []byte) []*pair.Match {
	return func(data []byte) []*pair.Match {
		res := []*pair.Match{}
		matches := runnerHostnameRe.FindAllSubmatchIndex(data, -1)
		for _, m := range matches {
			res = append(res, &pair.Match{
				Start: m[0],
				Value: data[m[2]:m[3]],
			})
		}
		return res
	}
}
