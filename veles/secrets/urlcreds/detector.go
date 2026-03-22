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

package urlcreds

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
	mongodbconnectionurl "github.com/google/osv-scalibr/veles/secrets/mongodburl"
)

const (
	// maxURLLength is an upper bound value for the length of a URL to be considered.
	// This helps limit the buffer size required for scanning.
	maxURLLength = 1_000
)

var (
	// urlPattern matches URLs containing credentials.
	// Format (per RFC 3986):
	//   scheme://username[:password]@host[/path][?query][#fragment]
	urlPattern = regexp.MustCompile(`\b[a-zA-Z0-9+.-]+:\/\/[^\s\?@#\/]+@[^\s]+\b`)
)

// isMongoDBScheme returns true if the URL scheme is mongodb or mongodb+srv.
func isMongoDBScheme(scheme string) bool {
	s := strings.ToLower(scheme)
	return s == "mongodb" || s == "mongodb+srv"
}

// NewDetector creates and returns a new instance of the URL with credentials detector.
// For MongoDB connection URLs (mongodb:// or mongodb+srv://), it returns a
// MongoDBConnectionURL secret instead of a generic Credentials secret, so that
// the MongoDB-specific validator can be used.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxURLLength,
		Re:     urlPattern,
		FromMatch: func(b []byte) (veles.Secret, bool) {
			u, err := url.Parse(string(b))
			if err != nil {
				return nil, false
			}
			if !hasValidCredentials(u) {
				return nil, false
			}
			if isMongoDBScheme(u.Scheme) {
				return mongodbconnectionurl.MongoDBConnectionURL{URL: string(b)}, true
			}
			return Credentials{FullURL: u.String()}, true
		},
	}
}

// hasValidCredentials returns true if a given url has valid credentials
func hasValidCredentials(u *url.URL) bool {
	if u.User == nil {
		return false
	}
	_, hasPassword := u.User.Password()
	return hasPassword || u.User.Username() != ""
}
