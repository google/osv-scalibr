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

package macapps

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata is the metadata struct for information parsed from the Info.plist file of a Mac App.
type Metadata struct {
	CFBundleDisplayName        string
	CFBundleIdentifier         string
	CFBundleShortVersionString string
	CFBundleExecutable         string
	CFBundleName               string
	CFBundlePackageType        string
	CFBundleSignature          string
	CFBundleVersion            string
	KSProductID                string
	KSUpdateURL                string
}

// ToProto converts the Metadata struct to a MacAppsMetadata proto.
func ToProto(m *Metadata) *pb.MacAppsMetadata {
	return &pb.MacAppsMetadata{
		BundleDisplayName:        m.CFBundleDisplayName,
		BundleIdentifier:         m.CFBundleIdentifier,
		BundleShortVersionString: m.CFBundleShortVersionString,
		BundleExecutable:         m.CFBundleExecutable,
		BundleName:               m.CFBundleName,
		BundlePackageType:        m.CFBundlePackageType,
		BundleSignature:          m.CFBundleSignature,
		BundleVersion:            m.CFBundleVersion,
		ProductId:                m.KSProductID,
		UpdateUrl:                m.KSUpdateURL,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the MacAppsMetadata proto to a Metadata struct.
func ToStruct(m *pb.MacAppsMetadata) *Metadata {

	return &Metadata{
		CFBundleDisplayName:        m.GetBundleDisplayName(),
		CFBundleIdentifier:         m.GetBundleIdentifier(),
		CFBundleShortVersionString: m.GetBundleShortVersionString(),
		CFBundleExecutable:         m.GetBundleExecutable(),
		CFBundleName:               m.GetBundleName(),
		CFBundlePackageType:        m.GetBundlePackageType(),
		CFBundleSignature:          m.GetBundleSignature(),
		CFBundleVersion:            m.GetBundleVersion(),
		KSProductID:                m.GetProductId(),
		KSUpdateURL:                m.GetUpdateUrl(),
	}
}
