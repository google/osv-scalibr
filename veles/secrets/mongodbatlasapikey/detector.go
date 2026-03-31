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

package mongodbatlasapikey

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/pair"
)

var (
	// publicKeyPattern matches MongoDB Atlas public API keys near identifying context.
	// Atlas public keys are 8 lowercase alphanumeric characters, but this pattern is too
	// generic on its own. We anchor it with context keywords that indicate an Atlas key.
	//
	// Matches patterns like:
	//   public_api_key = "yhrqvogk"
	//   MONGODB_ATLAS_PUBLIC_KEY=yhrqvogk
	//   "publicApiKey": "yhrqvogk"
	//   public_key: abcd1234
	publicKeyPattern = regexp.MustCompile(`(?i)(?:public[-_]?(?:api[-_]?)?key)["']?\s*[=:]\s*["'\x60]?([a-z0-9]{8})\b`)

	// privateKeyPattern matches MongoDB Atlas private API keys (UUID format) near context.
	// Atlas private keys are standard UUIDs (8-4-4-4-12 hex format).
	//
	// Matches patterns like:
	//   private_api_key = "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"
	//   MONGODB_ATLAS_PRIVATE_KEY=f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97
	//   "privateApiKey": "f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97"
	//   private_key: f2a79e29-8a44-4c75-a56d-5a4f7c6d1c97
	privateKeyPattern = regexp.MustCompile(`(?i)(?:private[-_]?(?:api[-_]?)?key)["']?\s*[=:]\s*["'\x60]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
)

const (
	// maxPublicKeyLen accounts for the context prefix + separators + the 8-char key value.
	maxPublicKeyLen = 80
	// maxPrivateKeyLen accounts for the context prefix + separators + the 36-char UUID value.
	maxPrivateKeyLen = 100
	// maxDistance is the maximum distance between public and private keys to be considered for pairing.
	// 10 KiB covers config files and environment variable blocks.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

// NewDetector returns a new Veles Detector that finds MongoDB Atlas API key pairs.
func NewDetector() veles.Detector {
	return &pair.Detector{
		MaxElementLen: max(maxPublicKeyLen, maxPrivateKeyLen),
		MaxDistance:   uint32(maxDistance),
		FindA:        pair.FindAllMatches(publicKeyPattern),
		FindB:        pair.FindAllMatches(privateKeyPattern),
		FromPair: func(p pair.Pair) (veles.Secret, bool) {
			pubSub := publicKeyPattern.FindSubmatch(p.A.Value)
			if len(pubSub) < 2 {
				return Credentials{}, false
			}
			privSub := privateKeyPattern.FindSubmatch(p.B.Value)
			if len(privSub) < 2 {
				return Credentials{}, false
			}
			return Credentials{
				PublicKey:  string(pubSub[1]),
				PrivateKey: string(privSub[1]),
			}, true
		},
	}
}
