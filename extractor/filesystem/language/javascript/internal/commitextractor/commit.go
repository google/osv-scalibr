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

// Package commitextractor provides a function to extract commit hash from the full git URL
package commitextractor

import (
	"net/url"
	"regexp"
	"slices"
)

// language=GoRegExp
var matchers = []*regexp.Regexp{
	// ssh://...
	// git://...
	// git+ssh://...
	// git+https://...
	regexp.MustCompile(`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`),
	// https://....git/...
	regexp.MustCompile(`(?:^|.+@)https://.+\.git#(\w+)$`),
	regexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`),
	regexp.MustCompile(`.+#commit[:=](\w+)$`),
	// github:...
	// gitlab:...
	// bitbucket:...
	regexp.MustCompile(`^(?:github|gitlab|bitbucket):.+#(\w+)$`),
}

// TryExtractCommit tries to extract the commit hash from a full git url.
func TryExtractCommit(resolution string) string {
	// Test with regexes first
	for _, re := range matchers {
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	// Otherwise, check if we can retrieve the hash from either the fragment or
	// the query ref
	u, err := url.Parse(resolution)

	if err != nil {
		return ""
	}

	gitRepoHosts := []string{
		"bitbucket.org",
		"github.com",
		"gitlab.com",
	}

	if !slices.Contains(gitRepoHosts, u.Host) {
		return ""
	}

	if u.RawQuery == "" {
		return u.Fragment
	}

	queries := u.Query()

	// Returns an empty string if there is no ref
	return queries.Get("ref")
}
