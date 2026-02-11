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

// Package denohelper provides common functionality for Deno extractors.
package denohelper

import (
	"net/url"
	"regexp"
	"strings"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denometadata"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Import specifier prefixes
	npmPrefix = "npm:"
	jsrPrefix = "jsr:"
)

// ParseImportSpecifier parses an import specifier and returns a Package if it's valid.
// Handles npm:, jsr:, and https:// prefixed imports.
func ParseImportSpecifier(specifier string) *extractor.Package {
	// Handle npm: prefixed imports (e.g., "npm:chalk@1")
	if pkgSpecifier, ok := strings.CutPrefix(specifier, npmPrefix); ok {
		packageName, packageVersion := ParseNPMNameAndVersion(pkgSpecifier)
		v, valid := CheckNPMNameAndVersion(packageName, packageVersion)
		if !valid {
			return nil
		} else if v != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  v,
				PURLType: purl.TypeNPM,
				Metadata: &denometadata.DenoMetadata{
					URL: specifier,
				},
			}
		}
	}
	// Handle jsr: prefixed imports (e.g., "jsr:@std1/path1@^1")
	if pkgSpecifier, ok := strings.CutPrefix(specifier, jsrPrefix); ok {
		name, version := ParseJSRNameAndVersion(pkgSpecifier)
		if name != "" && version != "" {
			return &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeJSR,
				Metadata: &denometadata.DenoMetadata{
					URL: specifier,
				},
			}
		}
	}
	// Handle https:// URLs
	if strings.HasPrefix(specifier, "https://") {
		return ParseHTTPSURL(specifier)
	}
	return nil
}

// ParseHTTPSURL parses HTTPS URLs and extracts package information from various CDN hosts.
func ParseHTTPSURL(specifier string) *extractor.Package {
	parsedURL, err := url.Parse(specifier)
	if err != nil {
		log.Debugf("failed to parse URL %s: %v", specifier, err)
		return nil
	}

	host := parsedURL.Host
	path := parsedURL.Path
	if path != "" && path[0] == '/' {
		path = path[1:] // Remove the leading slash
	}

	// Handle esm.sh imports
	if host == "esm.sh" {
		var packageName, packageVersion, purlType string

		// JSR imports (starts with /jsr/)
		if jsrPath, ok := strings.CutPrefix(path, "jsr/"); ok {
			// Example: https://esm.sh/jsr/@std/encoding@1.0.0/base64
			packageName, packageVersion = ParseJSRNameAndVersion(jsrPath)
			purlType = purl.TypeJSR
			// GitHub imports (starts with /gh/)
		} else if ghPath, ok := strings.CutPrefix(path, "gh/"); ok {
			// Example: https://esm.sh/gh/microsoft/tslib@v2.8.0
			parts := strings.Split(ghPath, "@")
			if len(parts) == 2 {
				packageName = parts[0]
				packageVersion = parts[1]
			}
			purlType = purl.TypeGithub
			// Default URL is NPM import
			// (e.g., "https://esm.sh/canvas-confetti@1.6.0")
		} else {
			packageName, packageVersion = ParseNPMNameAndVersion(path)
			purlType = purl.TypeNPM
		}

		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purlType,
				Metadata: &denometadata.DenoMetadata{
					FromESMCDN: true,
					URL:        specifier,
				},
			}
		}
	}

	// Handle deno.land/x imports (e.g., "https://deno.land/x/openai@v4.69.0/mod.ts")
	if host == "deno.land" && strings.HasPrefix(path, "x/") {
		// Extract the package name and version from a path
		packageName, packageVersion := ParseNPMNameAndVersion(strings.TrimPrefix(path, "x/"))
		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purl.TypeNPM,
				Metadata: &denometadata.DenoMetadata{
					FromDenolandCDN: true,
					URL:             specifier,
				},
			}
		}
	}

	// Handle unpkg.com imports (e.g., "https://unpkg.com/lodash-es@4.17.21/lodash.js")
	if host == "unpkg.com" {
		if path == "" {
			return nil
		}
		packageName, packageVersion := ParseNPMNameAndVersion(path)
		if packageName != "" && packageVersion != "" {
			return &extractor.Package{
				Name:     packageName,
				Version:  packageVersion,
				PURLType: purl.TypeNPM,
				Metadata: &denometadata.DenoMetadata{
					FromUnpkgCDN: true,
					URL:          specifier,
				},
			}
		}
	}

	return nil
}

// ParseNPMNameAndVersion parses the name and version from a npm package specifier.
// Handles both regular packages (e.g., "chalk@1") and scoped packages (e.g., "@types/node@14").
// Removes paths after the version (e.g., "chalk@1.0.0/dist/index.js").
// Trims the char "v" before the version
func ParseNPMNameAndVersion(specifier string) (name, version string) {
	specifier, _ = strings.CutPrefix(specifier, "@")
	// Extract the package name and version from the path
	packageParts := strings.SplitN(specifier, "@", 2)
	var extractedName, extractedVersion string
	if len(packageParts) == 2 {
		extractedName = packageParts[0]
		extractedVersion = packageParts[1]
		extractedVersion, _ = strings.CutPrefix(extractedVersion, "v")
		// Require the version to start with a numeric value
		if !regexp.MustCompile(`^\d`).MatchString(extractedVersion) {
			return "", ""
		}
		// Strip any trailing path after the version
		if idx := strings.Index(extractedVersion, "/"); idx != -1 {
			extractedVersion = extractedVersion[:idx]
		}
	}
	if len(packageParts) == 1 {
		return packageParts[0], ""
	}
	return extractedName, extractedVersion
}

// ParseJSRNameAndVersion parses the name and version from a JSR package specifier.
// Handles both regular packages and scoped packages (e.g., "@std/path@^1").
func ParseJSRNameAndVersion(specifier string) (name, version string) {
	specifier, _ = strings.CutPrefix(specifier, "@")
	parts := strings.SplitN(specifier, "@", 2)
	// "std/encoding@1.0.0/base64"
	if len(parts) == 2 {
		if strings.Contains(parts[1], "/") {
			return parts[0], strings.Split(parts[1], "/")[0]
		}

		return parts[0], parts[1]
	}
	return "", ""
}

// CheckNPMNameAndVersion checks if the NPM Package name is not empty and the version is a valid semver constraint.
func CheckNPMNameAndVersion(name, version string) (string, bool) {
	if name == "" || version == "" {
		return "", false
	}

	c, err := semver.NPM.ParseConstraint(version)
	if err != nil {
		log.Debugf("failed to parse NPM version constraint %s for dependency %s: %v", version, name, err)
		return "", false
	}

	v, err := c.CalculateMinVersion()
	if err != nil {
		log.Debugf("failed to calculate min NPM version for dependency %s with constraint %s: %v", name, version, err)
		return "", false
	}

	return v.Canon(false), true
}
