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

// Package linetracker provides utilities and custom structs to parse pom.xml files for the purpose
// of tracking line numbers of dependency declarations.
//
// The default Go XML parser will not track the offset or line numbers of the XML elements, so we
// need to implement a custom solution.
package linetracker

import (
	"bytes"
	"cmp"
	"encoding/xml"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/log"
)

// Dependency captures the line location and byte offset of a dependency as written in the XML file.
type Dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Offset     int64  `xml:"-"`
	Line       int    `xml:"-"`
}

// UnmarshalXML is implicitly called by Go's xml.Decoder to parse each <dependency> block.
// It intercepts decoding to record the tag's exact byte offset in the file.
func (td *Dependency) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	td.Offset = d.InputOffset()
	type alias Dependency
	var a alias
	if err := d.DecodeElement(&a, &start); err != nil {
		return err
	}
	td.GroupID = a.GroupID
	td.ArtifactID = a.ArtifactID
	td.Version = a.Version
	td.Type = a.Type
	td.Classifier = a.Classifier
	return nil
}

// matches checks if the raw XML dependency declaration matches the resolved package details.
func (td *Dependency) matches(groupID, artifactID, version, depType, classifier string) bool {
	if td.Version != "" &&
		// If td.Version is specified and doesn't contain a variable placeholder, it must match exactly.
		// If td.Version contains a placeholder, it will be handled later by `matchesPlaceholder`.
		(strings.Contains(td.Version, "${") || td.Version != version) {
		return false
	}
	// If td.Version is empty, it must match exactly.
	return td.GroupID == groupID &&
		td.ArtifactID == artifactID &&
		normalizeType(td.Type) == normalizeType(depType) &&
		td.Classifier == classifier
}

// normalizeType defaults an empty Maven dependency type to "jar".
func normalizeType(t string) string {
	if t == "" {
		return "jar"
	}
	return t
}

// FindLineNumberArgs encapsulates all parameters required by the line-matching algorithm.
type FindLineNumberArgs struct {
	GroupID    string
	ArtifactID string
	Version    string
	DepType    string
	Classifier string
	// RawDeps is the list of all raw dependency declarations extracted from the XML file.
	RawDeps []*Dependency
	// UsedRawDeps is a reservation table of raw dependency indices to prevent duplicate mappings.
	UsedRawDeps map[int]bool
	// ParentLine is the starting line of the <parent> block, used as a fallback for inherited dependencies.
	ParentLine int
	// InputPath is the absolute filesystem path of the child pom.xml, used for logging warnings.
	InputPath string
}

// FindLineNumber attempts to find the line number of a resolved dependency in the raw XML.
//
// There are three attempts to do a match:
//  1. Exact Match: Scans for a raw dependency matching the exact groupID, artifactID, version
//     (if hardcoded), type, and classifier.
//  2. Placeholder Match: Scans for raw dependencies where values use variable placeholders
//     (e.g., org.${group}.common) matching the resolved coordinates.
//  3. Parent Fallback: If no match is found (e.g., dependency inherited from a parent POM),
//     attributes the location to the <parent> declaration.
//
// If none of these succeed, the line number is set to 0.
func FindLineNumber(args FindLineNumberArgs) int {
	lineNum := 0

	// Attempt 1: Exact match on groupID, artifactID, version, type, and classifier fields.
	for i, raw := range args.RawDeps {
		// Skip already claimed lines to ensure one-to-one mapping.
		if args.UsedRawDeps[i] {
			continue
		}
		if raw.matches(args.GroupID, args.ArtifactID, args.Version, args.DepType, args.Classifier) {
			lineNum = raw.Line
			args.UsedRawDeps[i] = true
			break
		}
	}

	// Attempt 2: Match variable placeholders by prefix and suffix.
	if lineNum == 0 {
		var candidateIndices []int
		for i, raw := range args.RawDeps {
			// Skip lines already claimed by exact matches.
			if args.UsedRawDeps[i] {
				continue
			}
			if matchesPlaceholder(raw.GroupID, args.GroupID) &&
				matchesPlaceholder(raw.ArtifactID, args.ArtifactID) &&
				(raw.Version == "" || matchesPlaceholder(raw.Version, args.Version)) {
				candidateIndices = append(candidateIndices, i)
			}
		}
		if len(candidateIndices) == 1 {
			idx := candidateIndices[0]
			lineNum = args.RawDeps[idx].Line
			args.UsedRawDeps[idx] = true
		} else if len(candidateIndices) > 1 {
			// Ambiguous! Fallback to parent line or line 0
			log.Warnf("Ambiguous interpolation match for %s in %s", args.GroupID+":"+args.ArtifactID, args.InputPath)
		}
	}

	// Attempt 3: Fallback to parent line if present.
	if lineNum == 0 && args.ParentLine > 0 {
		lineNum = args.ParentLine
	}

	return lineNum
}

// shadowProject is a minimal representation of a Maven POM file used exclusively
// to extract the physical line numbers of dependency declarations.
type shadowProject struct {
	Dependencies []*Dependency   `xml:"dependencies>dependency"`
	Profiles     []shadowProfile `xml:"profiles>profile"`
	// Skip and exclude:
	// 1. <dependencyManagement> as SCALIBR only extracts active project dependencies.
	// 2. Build-only plugin dependencies (<build><plugins>) to prevent them from causing location misattribution.
}

// shadowProfile is a minimal representation of a Maven <profile> block.
type shadowProfile struct {
	Dependencies []*Dependency `xml:"dependencies>dependency"`
}

// RawDependencyLinesList parses the raw XML content to find all dependency declarations
// and calculate their line numbers based on their byte offsets.
func RawDependencyLinesList(content []byte) []*Dependency {
	var p shadowProject
	dec := datasource.NewMavenDecoder(bytes.NewReader(content))
	if err := dec.Decode(&p); err != nil {
		return nil
	}

	var allDeps []*Dependency
	allDeps = append(allDeps, p.Dependencies...)
	for _, prof := range p.Profiles {
		allDeps = append(allDeps, prof.Dependencies...)
	}

	// Sort by offset so we can do a single pass to find line numbers.
	slices.SortFunc(allDeps, func(a, b *Dependency) int {
		return cmp.Compare(a.Offset, b.Offset)
	})

	var lines []*Dependency
	currentOffset := int64(0)
	currentLine := 1
	for _, td := range allDeps {
		currentLine += bytes.Count(content[currentOffset:td.Offset], []byte{'\n'})
		currentOffset = td.Offset
		td.Line = currentLine
		lines = append(lines, td)
	}
	return lines
}

// ParentLine scans the raw XML for the <parent> tag. If present, it calculates
// and returns its starting line number.
func ParentLine(content []byte) int {
	dec := datasource.NewMavenDecoder(bytes.NewReader(content))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if t, ok := tok.(xml.StartElement); ok {
			if t.Name.Local == "parent" {
				return bytes.Count(content[:dec.InputOffset()], []byte{'\n'}) + 1
			}
		}
	}
	return 0
}

// matchesPlaceholder checks if a resolved value (e.g., "org.apache.common") could fit
// a raw value containing a single variable placeholder (e.g., "org.${group}.common").
//
// It scans the raw string for the opening "${" and closing "}" boundaries, extracting the
// prefix and suffix around the placeholder, and verifies if the resolved string matches them.
//
// Constraint: This function supports exactly one variable per element value.
func matchesPlaceholder(raw, resolved string) bool {
	if raw == resolved {
		return true
	}

	// Find the boundaries of the variable placeholder "${...}"
	start := strings.Index(raw, "${")
	if start == -1 {
		return false
	}
	end := strings.Index(raw, "}")
	if end == -1 || end < start {
		return false
	}

	// Extract the exact prefix and suffix from the original string
	prefix := raw[:start]
	suffix := raw[end+1:]

	// Verify the resolved value matches the hardcoded prefix and suffix boundaries.
	return len(resolved) >= len(prefix)+len(suffix) &&
		strings.HasPrefix(resolved, prefix) &&
		strings.HasSuffix(resolved, suffix)
}
