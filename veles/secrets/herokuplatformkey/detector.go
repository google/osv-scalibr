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

package herokuplatformkey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Detector = NewSecretKeyDetector()
)

// keyMaxLen defines the maximum allowed size of a Heroku Platform API Key.
//
// Heroku OAuth access tokens are 65 characters long and prefixed with HRKU-.
// https://devcenter.heroku.com/articles/oauth#prefixed-oauth-tokens
const keyMaxLen = 65

// Platform API Keys can be found with this regex, ex: HRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo
var keyRe = regexp.MustCompile(`\b(HRKU-[0-9a-zA-Z_-]{60})\b`)

// NewSecretKeyDetector returns a detector for Heroku Platform Keys (HRKU-...).
func NewSecretKeyDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: keyMaxLen,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return HerokuSecret{Key: string(b)}, true
		},
	}
}
