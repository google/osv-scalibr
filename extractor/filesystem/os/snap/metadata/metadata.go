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

// Package metadata defines a metadata struct for SNAP packages.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a SNAP package.
type Metadata struct {
	Name              string
	Version           string
	Grade             string
	Type              string
	Architectures     []string
	OSID              string
	OSVersionCodename string
	OSVersionID       string
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
	// e.g. jammy
	if m.OSVersionCodename != "" {
		return m.OSVersionCodename
	}
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		log.Warnf("VERSION_CODENAME not set in os-release, fallback to VERSION_ID")
		return m.OSVersionID
	}
	log.Errorf("VERSION_CODENAME and VERSION_ID not set in os-release")
	return ""
}

// SetProto sets the SNAPPackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_SnapMetadata{
		SnapMetadata: &pb.SNAPPackageMetadata{
			Name:              m.Name,
			Version:           m.Version,
			Grade:             m.Grade,
			Type:              m.Type,
			Architectures:     m.Architectures,
			OsId:              m.OSID,
			OsVersionCodename: m.OSVersionCodename,
			OsVersionId:       m.OSVersionID,
		},
	}
}

// ToStruct converts the SNAPPackageMetadata proto to a Metadata struct.
func ToStruct(m *pb.SNAPPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Name:              m.GetName(),
		Version:           m.GetVersion(),
		Grade:             m.GetGrade(),
		Type:              m.GetType(),
		Architectures:     m.GetArchitectures(),
		OSID:              m.GetOsId(),
		OSVersionCodename: m.GetOsVersionCodename(),
		OSVersionID:       m.GetOsVersionId(),
	}
}
