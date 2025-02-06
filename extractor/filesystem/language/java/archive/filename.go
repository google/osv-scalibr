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

package archive

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Regexes to determine if a string is a version
var (
	digit           = regexp.MustCompile("^[0-9]")
	buildAndDigit   = regexp.MustCompile("^build[0-9]")
	releaseAndDigit = regexp.MustCompile("^rc?[0-9]+([^a-zA-Z]|$)")
)

// JarProps stores the name, version, and group ID of a Java archive.
type JarProps struct {
	ArtifactID string
	Version    string
	GroupID    string
}

// ParseFilename attempts to figure out the package name, version, and group ID of a
// Java archive based on its filename. Returns nil if parsing was unsuccessful.
func ParseFilename(filePath string) *JarProps {
	name, version := nameVersionFromFilename(filePath)
	if version == "" {
		return nil
	}
	groupID := ""
	i := strings.LastIndex(name, ".")
	if i >= 0 {
		// Most JAR files only contain the artifact ID in the name, so the group ID
		// cannot usually be determined strictly from the filename. However, since
		// the format of artifact ID is arbitrarily determined by developers,
		// sometimes they are namespaced to the group ID (e.g. for
		// org.apache.felix.framework-1.2.3.jar the group ID is org.apache.felix).
		// We attempt to extract such group IDs here.
		groupID = name[:i]
	}
	return &JarProps{ArtifactID: name, Version: version, GroupID: groupID}
}

func nameVersionFromFilename(filePath string) (string, string) {
	base := filepath.Base(filePath)
	filename := strings.TrimSuffix(base, filepath.Ext(base))
	if strings.Contains(filename, "-") {
		// Most archive names follow the convention "some-package-name-1.2.3"
		// There might be dashes in the version too, e.g. "guava-31.1-jre"
		for i, c := range filename {
			if c != '-' {
				continue
			}
			v := filename[i+1:]
			if isVersion(v) {
				return filename[:i], v
			}
		}
	}
	// Also try package_version and package.version
	for _, sep := range []string{"_", "."} {
		i := strings.Index(filename, sep)
		if i == -1 {
			continue
		}
		v := filename[i+1:]
		if isVersion(v) {
			return filename[:i], v
		}
	}
	// Version could not be determined.
	return filename, ""
}

func isVersion(str string) bool {
	if digit.MatchString(str) {
		return true
	}
	if buildAndDigit.MatchString(str) {
		return true
	}
	return releaseAndDigit.MatchString(str)
}
