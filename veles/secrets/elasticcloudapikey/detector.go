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

package elasticcloudapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the maximum size of an Elastic Cloud API key.
// Pattern: "essu_" + a 92-character base64 segment (may include 0â€“2 '=' padding).
const maxTokenLength = 97

// keyRe matches an Elastic Cloud API key.
// Keys start with "essu_" followed by a 92-character Base64 segment.
// The last two characters may include 0–2 '=' padding characters.
var keyRe = regexp.MustCompile(`essu_(?:[A-Za-z0-9+/]{92}|[A-Za-z0-9+/]{91}=|[A-Za-z0-9+/]{90}==)`)

// NewDetector returns a new simpletoken.Detector that matches
// Elastic Cloud API keys.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return ElasticCloudAPIKey{Key: string(b)}, true
		},
	}
}
