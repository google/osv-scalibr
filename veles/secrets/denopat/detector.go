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

// Package denopat contains Veles Secret types and Detectors for
// Deno Personal Access Tokens (user tokens with prefix `ddp_` and organization tokens with prefix `ddo_`).
package denopat

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of a Deno PAT.
const maxTokenLength = 40

// userPatRe is a regular expression that matches a Deno User Personal Access Token.
// User PATs have the form: `ddp_` followed by 36 alphanumeric characters.
var userPatRe = regexp.MustCompile(`ddp_[A-Za-z0-9]{36}`)

// orgPatRe is a regular expression that matches a Deno Organization Personal Access Token.
// Organization PATs have the form: `ddo_` followed by 36 alphanumeric characters.
var orgPatRe = regexp.MustCompile(`ddo_[A-Za-z0-9]{36}`)

var _ veles.Detector = NewUserTokenDetector()
var _ veles.Detector = NewOrgTokenDetector()

// NewUserTokenDetector returns a new Detector that matches
// Deno User Personal Access Tokens (prefix `ddp_`).
func NewUserTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     userPatRe,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			return DenoUserPAT{Pat: string(match)}, true
		},
	}
}

// NewOrgTokenDetector returns a new Detector that matches
// Deno Organization Personal Access Tokens (prefix `ddo_`).
func NewOrgTokenDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     orgPatRe,
		FromMatch: func(match []byte) (veles.Secret, bool) {
			return DenoOrgPAT{Pat: string(match)}, true
		},
	}
}
