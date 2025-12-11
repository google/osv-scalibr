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

package gcshmackey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	// ref: https://cloud.google.com/storage/docs/authentication/hmackeys#overview
	accessIDPattern = regexp.MustCompile(`GOOG(?:[A-Z0-9]{57}|[A-Z0-9]{20})`)
	secretPattern   = regexp.MustCompile(`[A-Za-z0-9+/]{40}`)
)

const (
	maxAccessIDLen = 61
	maxSecretLen   = 40
	// maxDistance is the maximum distance between AccessID and secrets to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// NewDetector returns a new Veles Detector that finds Google Cloud Storage HMAC keys
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxAccessIDLen, maxSecretLen), MaxDistance: uint32(maxDistance),
		FindA: pair.FindAllMatches(accessIDPattern),
		FindB: pair.FindAllMatches(secretPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			return HMACKey{AccessID: string(p.A.Value), Secret: string(p.B.Value)}, true
		},
	}
}
