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

// Package metadata defined a Metadata struct for DPKG packages.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a dpkg package.
type Metadata struct {
	PackageName       string
	Status            string
	SourceName        string
	SourceVersion     string
	PackageVersion    string
	OSID              string
	OSVersionCodename string
	OSVersionID       string
	Maintainer        string
	Architecture      string
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	// TODO(b/298152210): Implement metric
	return "linux"
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

// SetProto sets the DPKGPackageMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_DpkgMetadata{
		DpkgMetadata: &pb.DPKGPackageMetadata{
			PackageName:       m.PackageName,
			Status:            m.Status,
			SourceName:        m.SourceName,
			SourceVersion:     m.SourceVersion,
			PackageVersion:    m.PackageVersion,
			OsId:              m.OSID,
			OsVersionCodename: m.OSVersionCodename,
			OsVersionId:       m.OSVersionID,
			Maintainer:        m.Maintainer,
			Architecture:      m.Architecture,
		},
	}
}

// ToStruct converts the NetportsMetadata proto to a Metadata struct.
func ToStruct(m *pb.DPKGPackageMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		PackageName:       m.GetPackageName(),
		Status:            m.GetStatus(),
		SourceName:        m.GetSourceName(),
		SourceVersion:     m.GetSourceVersion(),
		PackageVersion:    m.GetPackageVersion(),
		OSID:              m.GetOsId(),
		OSVersionCodename: m.GetOsVersionCodename(),
		OSVersionID:       m.GetOsVersionId(),
		Maintainer:        m.GetMaintainer(),
		Architecture:      m.GetArchitecture(),
	}
}
