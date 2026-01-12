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

// Package containerdmetadata defines the metadata for the containerd standalone extractor.
package containerdmetadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata holds parsing information for a container running on the containerd runtime.
type Metadata struct {
	Namespace   string
	ImageName   string
	ImageDigest string
	Runtime     string
	ID          string
	PID         int
	RootFS      string
}

// SetProto sets the CtrdRuntimeMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil || p == nil {
		return
	}

	p.Metadata = &pb.Package_ContainerdRuntimeContainerMetadata{
		ContainerdRuntimeContainerMetadata: &pb.ContainerdRuntimeContainerMetadata{
			NamespaceName: m.Namespace,
			ImageName:     m.ImageName,
			ImageDigest:   m.ImageDigest,
			Runtime:       m.Runtime,
			Id:            m.ID,
			Pid:           int32(m.PID),
			RootfsPath:    m.RootFS,
		},
	}
}

// ToStruct converts the CtrdRuntimeMetadata proto to a Metadata struct.
func ToStruct(m *pb.ContainerdRuntimeContainerMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Namespace:   m.GetNamespaceName(),
		ImageName:   m.GetImageName(),
		ImageDigest: m.GetImageDigest(),
		Runtime:     m.GetRuntime(),
		ID:          m.GetId(),
		PID:         int(m.GetPid()),
		RootFS:      m.GetRootfsPath(),
	}
}
