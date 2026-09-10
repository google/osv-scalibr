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

package aspect

import (
	"regexp"
	"strings"
)

var (
	reURL1 = regexp.MustCompile(`/v?(\d+\.\d+\.\d+(?:[\.-][a-zA-Z0-9\.]+)?)(?:/|$)`)
	reURL2 = regexp.MustCompile(`/v?(\d+\.\d+)(?:/|$)`)
	reURL3 = regexp.MustCompile(`[-_]v?(\d+\.\d+(?:\.\d+)*(?:[-_.][a-zA-Z0-9]+)?)(?:[-_]|\.tar|\.zip|\.jar|$)`)
	reURL4 = regexp.MustCompile(`(?:^|[-_/])v?(\d{8})(?:[-_.]|$)`)

	reStrip1 = regexp.MustCompile(`(?:^|[-_.])v?(\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9\.]+)?)$`)
	reStrip2 = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	reStrip3 = regexp.MustCompile(`(\d+\.\d+)`)
)

func cleanVersion(version string) string {
	if version == "" {
		return ""
	}
	version = strings.TrimSpace(version)
	version = strings.TrimRight(version, `/\`)
	version = strings.TrimSpace(version)

	exts := []string{
		".tar.gz.sig", ".tar.gz", ".tar.xz", ".tar.bz2", ".zip", ".jar", ".tgz", ".deb", ".whl", ".sig",
	}
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(version), ext) {
			version = version[:len(version)-len(ext)]
			break
		}
	}
	if (strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V")) && len(version) > 1 && (version[1] >= '0' && version[1] <= '9') {
		version = version[1:]
	}
	version = strings.TrimRight(version, ".")
	if version != "" {
		return version
	}
	return ""
}

func extractVersionFromURL(url string) string {
	if url == "" {
		return ""
	}

	// 1. Try to find a path segment that is a 3-part version
	if m := reURL1.FindStringSubmatch(url); len(m) > 1 {
		return cleanVersion(m[1])
	}

	// 2. Try to find a 2-part path segment version
	if m := reURL2.FindStringSubmatch(url); len(m) > 1 {
		return cleanVersion(m[1])
	}

	// 3. Try to find a version in filename part
	parts := strings.Split(url, "/")
	filename := parts[len(parts)-1]
	if m := reURL3.FindStringSubmatch(filename); len(m) > 1 {
		return cleanVersion(m[1])
	}

	// 4. Try date-based 8 digit version in filename
	if m := reURL4.FindStringSubmatch(filename); len(m) > 1 {
		return cleanVersion(m[1])
	}
	return ""
}

func extractVersionFromStripPrefix(stripPrefix string) string {
	if stripPrefix == "" {
		return ""
	}
	stripPrefix = strings.TrimSpace(stripPrefix)
	stripPrefix = strings.TrimRight(stripPrefix, `/\`)
	stripPrefix = strings.TrimSpace(stripPrefix)

	if m := reStrip1.FindStringSubmatch(stripPrefix); len(m) > 1 {
		return cleanVersion(m[1])
	}
	if m := reStrip2.FindStringSubmatch(stripPrefix); len(m) > 1 {
		return cleanVersion(m[1])
	}
	if m := reStrip3.FindStringSubmatch(stripPrefix); len(m) > 1 {
		return cleanVersion(m[1])
	}
	return ""
}
