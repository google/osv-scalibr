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

// Package metadata defines a metadata struct for kernel vmlinuz files.
package metadata

import (
	"github.com/google/osv-scalibr/log"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a kernel vmlinuz file.
type Metadata struct {
	Name              string
	Version           string
	Architecture      string
	ExtendedVersion   string
	Format            string
	SwapDevice        int32
	RootDevice        int32
	VideoMode         string
	OSID              string
	OSVersionCodename string
	OSVersionID       string
	RWRootFS          bool
}

// SetProto sets the vmlinuz metadata on the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil || p == nil {
		return
	}
	p.Metadata = &pb.Package_VmlinuzMetadata{
		VmlinuzMetadata: &pb.VmlinuzMetadata{
			Name:              m.Name,
			Version:           m.Version,
			Architecture:      m.Architecture,
			ExtendedVersion:   m.ExtendedVersion,
			Format:            m.Format,
			SwapDevice:        m.SwapDevice,
			RootDevice:        m.RootDevice,
			VideoMode:         m.VideoMode,
			OsId:              m.OSID,
			OsVersionCodename: m.OSVersionCodename,
			OsVersionId:       m.OSVersionID,
			RwRootFs:          m.RWRootFS,
		},
	}
}

// ToStruct converts a Package proto to a vmlinuz metadata struct.
func ToStruct(m *pb.VmlinuzMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Name:              m.GetName(),
		Version:           m.GetVersion(),
		Architecture:      m.GetArchitecture(),
		ExtendedVersion:   m.GetExtendedVersion(),
		Format:            m.GetFormat(),
		SwapDevice:        m.GetSwapDevice(),
		RootDevice:        m.GetRootDevice(),
		VideoMode:         m.GetVideoMode(),
		OSID:              m.GetOsId(),
		OSVersionCodename: m.GetOsVersionCodename(),
		OSVersionID:       m.GetOsVersionId(),
		RWRootFS:          m.GetRwRootFs(),
	}
}

// ToNamespace extracts the PURL namespace from the metadata.
func (m *Metadata) ToNamespace() string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	return "linux"
}

// ToDistro extracts the OS distro from the metadata.
func (m *Metadata) ToDistro() string {
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}
