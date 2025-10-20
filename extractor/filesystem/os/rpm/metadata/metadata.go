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

// Package metadata defines a metadata struct for rpm packages.
package metadata

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	// pattern to match: openEuler version (qualifier)
	// where (qualifier) is optional. Those without qualifier are considered innovation versions.
	// version: YY.MM format. e.g. 24.03
	// qualifier: currently supported are LTS, LTS SPd. e.g. LTS, LTS-SP1, LTS-SP2
	openEulerPrettyNameRegexp = regexp.MustCompile(`^openEuler\s+([0-9]{2}\.[0-9]{2})(?:\s*\((LTS(?:[- ]SP\d+)?)\))?$`)
)

// Metadata holds parsing information for an rpm package.
type Metadata struct {
	PackageName  string
	SourceRPM    string
	Epoch        int
	OSName       string
	OSPrettyName string
	OSID         string
	OSVersionID  string
	OSBuildID    string
	Vendor       string
	Architecture string
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to ''")
	return ""
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	v := m.OSVersionID
	if v == "" {
		v = m.OSBuildID
		if v == "" {
			log.Errorf("VERSION_ID and BUILD_ID not set in os-release")
			return ""
		}
		log.Errorf("os-release[VERSION_ID] not set, fallback to BUILD_ID")
	}

	id := m.OSID
	if id == "" {
		log.Errorf("os-release[ID] not set, fallback to ''")
		return v
	}
	return fmt.Sprintf("%s-%s", id, v)
}

// SetProto sets the RPMPackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_RpmMetadata{
		RpmMetadata: &pb.RPMPackageMetadata{
			PackageName:  m.PackageName,
			SourceRpm:    m.SourceRPM,
			Epoch:        int32(m.Epoch),
			OsName:       m.OSName,
			OsPrettyName: m.OSPrettyName,
			OsId:         m.OSID,
			OsVersionId:  m.OSVersionID,
			OsBuildId:    m.OSBuildID,
			Vendor:       m.Vendor,
			Architecture: m.Architecture,
		},
	}
}

// ToStruct converts the RPMPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.RPMPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		PackageName:  m.GetPackageName(),
		SourceRPM:    m.GetSourceRpm(),
		Epoch:        int(m.GetEpoch()),
		OSName:       m.GetOsName(),
		OSPrettyName: m.GetOsPrettyName(),
		OSID:         m.GetOsId(),
		OSVersionID:  m.GetOsVersionId(),
		OSBuildID:    m.GetOsBuildId(),
		Vendor:       m.GetVendor(),
		Architecture: m.GetArchitecture(),
	}
}

// OpenEulerEcosystemSuffix returns the normalized ecosystem suffix for openEuler RPMs with uses of pretty name.
// e.g. openEuler 24.03 (LTS) -> 24.03-LTS
func (m *Metadata) OpenEulerEcosystemSuffix() string {
	if m == nil {
		return ""
	}

	prettyName := strings.TrimSpace(m.OSPrettyName)
	if prettyName != "" {
		if matches := openEulerPrettyNameRegexp.FindStringSubmatch(prettyName); len(matches) > 0 {
			version := matches[1]
			qualifier := strings.TrimSpace(matches[2])
			if qualifier == "" {
				return version
			}

			qualifier = strings.ReplaceAll(qualifier, " ", "-")
			qualifier = strings.Trim(qualifier, "-")
			if qualifier == "" {
				return version
			}

			return version + "-" + qualifier
		}
	}

	versionID := strings.TrimSpace(m.OSVersionID)
	return versionID
}
