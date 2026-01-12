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

package codecommit

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth"
)

// NewValidator creates a new Validator that validates CodeCommit credentials
func NewValidator() *simplevalidate.Validator[Credentials] {
	return gitbasicauth.NewValidator[Credentials](
		func(u *url.URL) bool {
			return strings.HasPrefix(u.Host, "git-codecommit.") && strings.HasSuffix(u.Host, ".amazonaws.com")
		},
		[]int{http.StatusOK, http.StatusNotFound}, []int{http.StatusForbidden},
	)
}
