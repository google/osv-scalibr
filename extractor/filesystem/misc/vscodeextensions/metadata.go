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

package vscodeextensions

import (
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata for VS Code extensions.
type Metadata struct {
	ID                   string `json:"id"`
	PublisherID          string `json:"publisherId"`
	PublisherDisplayName string `json:"publisherDisplayName"`
	TargetPlatform       string `json:"targetPlatform"`
	Updated              bool   `json:"updated"`
	IsPreReleaseVersion  bool   `json:"isPreReleaseVersion"`
	InstalledTimestamp   int64  `json:"installedTimestamp"`
}

// ToProto converts the Metadata struct to a VSCodeExtensionsMetadata proto.
func ToProto(m *Metadata) *pb.VSCodeExtensionsMetadata {
	return &pb.VSCodeExtensionsMetadata{
		Id:                   m.ID,
		PublisherId:          m.PublisherID,
		PublisherDisplayName: m.PublisherDisplayName,
		TargetPlatform:       m.TargetPlatform,
		Updated:              m.Updated,
		IsPreReleaseVersion:  m.IsPreReleaseVersion,
		InstalledTimestamp:   m.InstalledTimestamp,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the VSCodeExtensionsMetadata proto to a Metadata struct.
func ToStruct(m *pb.VSCodeExtensionsMetadata) *Metadata {

	return &Metadata{
		ID:                   m.GetId(),
		PublisherID:          m.GetPublisherId(),
		PublisherDisplayName: m.GetPublisherDisplayName(),
		TargetPlatform:       m.GetTargetPlatform(),
		Updated:              m.GetUpdated(),
		IsPreReleaseVersion:  m.GetIsPreReleaseVersion(),
		InstalledTimestamp:   m.GetInstalledTimestamp(),
	}
}
