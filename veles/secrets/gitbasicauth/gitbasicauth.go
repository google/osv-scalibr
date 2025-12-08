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

// Package gitbasicauth contains common logic for Git Basic Auth plugins.
package gitbasicauth

import (
	"net/url"
)

// Info returns the URL for the Git info/refs endpoint with service=git-upload-pack.
func Info(repoURL *url.URL) *url.URL {
	u := repoURL.JoinPath("info/refs")
	u.RawQuery = "service=git-upload-pack"
	return u
}
