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

// Package pomxml extracts pom.xml files.
package pomxml

import (
	"context"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// "Constant" at the top to compile this regex only once.
var (
	versionRequirementReg = regexp.MustCompile(`[[(]?(.*?)(?:,|[)\]]|$)`)
	interpolationReg      = regexp.MustCompile(`\${(.+)}`)
)

type mavenLockDependency struct {
	XMLName    xml.Name `xml:"dependency"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Scope      string   `xml:"scope"`
	Type       string   `xml:"type"`
	Classifier string   `xml:"classifier"`
}

func (mld mavenLockDependency) parseResolvedVersion(version string) string {
	results := versionRequirementReg.FindStringSubmatch(version)
	// First capture group will always exist, but might be empty, therefore the slice will always
	// have a length of 2.
	if results == nil || results[1] == "" {
		return "0"
	}

	return results[1]
}

func (mld mavenLockDependency) resolveVersionValue(lockfile mavenLockFile) string {
	// results will always either be nil or have a length of 2
	results := interpolationReg.FindStringSubmatch(mld.Version)

	// no interpolation, so just return the version as-is
	if results == nil {
		return mld.Version
	}
	if val, ok := lockfile.Properties.m[results[1]]; ok {
		return val
	}

	log.Errorf(
		"Failed to resolve version of %s: property \"%s\" could not be found for \"%s\"\n",
		mld.GroupID+":"+mld.ArtifactID,
		results[1],
		lockfile.GroupID+":"+lockfile.ArtifactID,
	)

	return "0"
}

func (mld mavenLockDependency) ResolveVersion(lockfile mavenLockFile) string {
	version := mld.resolveVersionValue(lockfile)

	return mld.parseResolvedVersion(version)
}

type mavenLockFile struct {
	XMLName             xml.Name              `xml:"project"`
	ModelVersion        string                `xml:"modelVersion"`
	GroupID             string                `xml:"groupId"`
	ArtifactID          string                `xml:"artifactId"`
	Properties          mavenLockProperties   `xml:"properties"`
	Dependencies        []mavenLockDependency `xml:"dependencies>dependency"`
	ManagedDependencies []mavenLockDependency `xml:"dependencyManagement>dependencies>dependency"`
}

type mavenLockProperties struct {
	m map[string]string
}

func (p *mavenLockProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.m = map[string]string{}

	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tt := t.(type) {
		case xml.StartElement:
			var s string

			if err := d.DecodeElement(&s, &tt); err != nil {
				return fmt.Errorf("%w", err)
			}

			p.m[tt.Name.Local] = s

		case xml.EndElement:
			if tt.Name == start.Name {
				return nil
			}
		}
	}
}

// Extractor extracts Maven packages from pom.xml files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "java/pomxml" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "pom.xml"
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *mavenLockFile

	err := xml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	details := map[string]*extractor.Inventory{}

	for _, lockPackage := range parsedLockfile.ManagedDependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID
		metadata := javalockfile.Metadata{
			ArtifactID:   lockPackage.ArtifactID,
			GroupID:      lockPackage.GroupID,
			DepGroupVals: []string{},
		}

		pkgDetails := &extractor.Inventory{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Locations: []string{input.Path},
			Metadata:  &metadata,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			metadata.DepGroupVals = []string{scope}
		}
		details[finalName] = pkgDetails
	}

	// standard dependencies take precedent over managed dependencies
	for _, lockPackage := range parsedLockfile.Dependencies {
		finalName := lockPackage.GroupID + ":" + lockPackage.ArtifactID
		metadata := javalockfile.Metadata{
			ArtifactID:   lockPackage.ArtifactID,
			GroupID:      lockPackage.GroupID,
			Type:         lockPackage.Type,
			Classifier:   lockPackage.Classifier,
			DepGroupVals: []string{},
		}
		pkgDetails := &extractor.Inventory{
			Name:      finalName,
			Version:   lockPackage.ResolveVersion(*parsedLockfile),
			Locations: []string{input.Path},
			Metadata:  &metadata,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			metadata.DepGroupVals = []string{scope}
		}
		details[finalName] = pkgDetails
	}

	return maps.Values(details), nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*javalockfile.Metadata)
	return &purl.PackageURL{
		Type:      purl.TypeMaven,
		Namespace: strings.ToLower(m.GroupID),
		Name:      strings.ToLower(m.ArtifactID),
		Version:   i.Version,
		Qualifiers: purl.QualifiersFromMap(map[string]string{
			purl.Type:       m.Type,
			purl.Classifier: m.Classifier,
		}),
	}
}

// Ecosystem returns the OSV ecosystem ('Maven') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "Maven"
}

var _ filesystem.Extractor = Extractor{}
