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

// Package mongodbconnectionurl contains a Veles Secret type and a Detector for
// MongoDB connection URLs with embedded credentials.
package mongodbconnectionurl

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxURLLength is the maximum size of a MongoDB connection URL we expect to find.
// MongoDB URIs can be long due to options, replica set hosts, etc.
const maxURLLength = 4096

// mongoURIRe matches MongoDB connection URLs that contain credentials (user:password@host).
// It supports both mongodb:// and mongodb+srv:// schemes.
// The regex requires a username and password separated by a colon before the @ sign.
//
// Per the MongoDB connection string spec, the following characters in the
// username or password must be percent-encoded: $ : / ? # [ ] @
// For example, '@' becomes '%40', ':' becomes '%3A', etc.
// The regex handles percent-encoded characters naturally since '%' and hex
// digits are allowed by the character classes.
//
// Matched examples:
//
//	mongodb://myUser:myPass@localhost
//	mongodb://myUser:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin
//	mongodb+srv://myUser:myPass@cluster0.example.net/myDB?retryWrites=true
var mongoURIRe = regexp.MustCompile(`mongodb(?:\+srv)?://[^\s:@/]+:[^\s@/]+@[^\s]+`)

// NewDetector returns a new simpletoken.Detector that matches
// MongoDB connection URLs with embedded credentials.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxURLLength,
		Re:     mongoURIRe,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			return MongoDBConnectionURL{URL: string(b)}, true
		},
	}
}
