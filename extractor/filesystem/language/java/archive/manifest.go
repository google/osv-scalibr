// Copyright 2024 Google LLC
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
	"archive/zip"
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/log"
)

// manifest for identifying Maven package.
type manifest struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// valid returns true if mf is a valid manifest property.
func (mf manifest) valid() bool {
	return mf.GroupID != "" && mf.ArtifactID != "" && mf.Version != ""
}

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, fmt.Errorf("failed to open file %q: %w", f.Name, err)
	}
	defer file.Close()

	log.Debugf("Parsing manifest file %s\n", f.Name)

	rd := textproto.NewReader(bufio.NewReader(file))
	h, err := rd.ReadMIMEHeader()
	// MIME header require \n\n in the end, while MANIFEST.mf might not have this. Headers before are
	// parsed correctly anyway, so skip the error and continue.
	if err != nil && !errors.Is(err, io.EOF) {
		return manifest{}, fmt.Errorf("failed to read MIME header: %w", err)
	}

	return manifest{
		GroupID:    getGroupID(h),
		ArtifactID: getArtifactID(h),
		Version:    getVersion(h),
	}, nil
}

// Transforms for manifest fields that need a little work to extract the group
// ID. Note that we intentionally do not combine this as part of the `keys` in
// the `getGroupID` function because we want to maintain ordering of the keys to
// preserve priority of fields.
var groupIDTransforms = map[string]func(string) string{

	// The `Implementation-Title` field can have the group ID as the first part of
	// the value, with other info appended to it.  To extract it, we simply try to
	// pull out the first domain-like string in the value.
	//
	// For example, elasticsearch-8.14.3.jar has a manifest with the following:
	//
	//	Implementation-Title: org.elasticsearch#server;8.14.3
	//
	// And we simply want to extract `org.elasticsearch`, which would be the first
	// match for the regex.
	"Implementation-Title": func(s string) string {
		groupIDRegex, err := regexp.Compile(`[a-zA-Z0-9-_\.]+`)
		if err != nil {
			log.Warnf("Error compiling group ID regex: %v", err)
		}

		// Get the first match for a domain-like string.
		return groupIDRegex.FindString(s)
	},
}

func getGroupID(h textproto.MIMEHeader) string {
	keys := []string{
		"Bundle-SymbolicName",
		"Extension-Name",
		"Specification-Vendor",
		"Implementation-Vendor",
		"Implementation-Vendor-Id",
		"Implementation-Title",
		"Bundle-Activator",
		"Automatic-Module-Name",
		"Main-Class",
		"Package",
	}
	log.Debug("Potential group ids:")
	for _, k := range keys {
		log.Debugf("  %s: %s\n", k, h.Get(k))
	}

	g := getFirstValidGroupID(h, keys)
	if strings.Contains(g, ";") {
		g = strings.Split(g, ";")[0]
	}
	return g
}

func getFirstValidGroupID(h textproto.MIMEHeader, names []string) string {
	for _, n := range names {
		groupID := h.Get(n)
		if transform, ok := groupIDTransforms[n]; ok {
			groupID = transform(groupID)
		}
		if validGroupID(groupID) {
			return strings.ToLower(groupID)
		}
	}
	return ""
}

func validGroupID(name string) bool {
	return name != "" && !strings.Contains(name, " ")
}

func getArtifactID(h textproto.MIMEHeader) string {
	id := getArtifactIDForBundlePlugin(h)
	if id != "" {
		return id
	}

	keys := []string{
		"Name",
		"Implementation-Title",
		"Specification-Title",
		"Bundle-Name",
		"Short-Name",
		"Extension-Name",
	}
	log.Debug("Potential artifact ids:")
	for _, k := range keys {
		log.Debugf("  %s: %s\n", k, h.Get(k))
	}
	return getFirstValidArtifactID(h, keys)
}

func getVersion(h textproto.MIMEHeader) string {
	keys := []string{
		"Implementation-Version",
		"Specification-Version",
		"Plugin-Version",
		"Bundle-Version",
	}
	log.Debug("Potential version:")
	for _, k := range keys {
		log.Debugf("  %s: %s\n", k, h.Get(k))
	}
	return getFirst(h, keys)
}

func getFirst(h textproto.MIMEHeader, names []string) string {
	for _, n := range names {
		if h.Get(n) != "" {
			return h.Get(n)
		}
	}
	return ""
}

// getArtifactIDForBundlePlugin returns the package name for an Apache Maven Bundle Plugin.
//
// For these plugins, the package name is the last part of `Bundle-SymbolicName`.
// For example, the package for `Bundle-SymbolicName: com.google.guava.failureaccess` is `failureaccess`
// https://svn.apache.org/repos/asf/felix/releases/maven-bundle-plugin-1.2.0/doc/maven-bundle-plugin-bnd.html
// https://felix.apache.org/documentation/subprojects/apache-felix-maven-bundle-plugin-bnd.html
func getArtifactIDForBundlePlugin(h textproto.MIMEHeader) string {
	if h.Get("Created-By") != "Apache Maven Bundle Plugin" {
		return ""
	}
	symbolicName := h.Get("Bundle-SymbolicName")
	if symbolicName == "" {
		return ""
	}
	parts := strings.Split(symbolicName, ".")

	artifactID := parts[len(parts)-1]
	if validArtifactID(artifactID) {
		return artifactID
	}

	return ""
}

func getFirstValidArtifactID(h textproto.MIMEHeader, names []string) string {
	for _, n := range names {
		if validArtifactID(h.Get(n)) {
			return h.Get(n)
		}
	}
	return ""
}

func validArtifactID(name string) bool {
	if name == "" || strings.Contains(name, " ") {
		return false
	}

	// e.g. "${org.eclipse.jdt.annotation.bundleName}"
	// b/298196886#comment9
	if strings.HasPrefix(name, "$") {
		return false
	}

	// e.g. "%pluginName"
	// b/298196886#comment10
	if strings.HasPrefix(name, "%") {
		return false
	}

	return true
}
