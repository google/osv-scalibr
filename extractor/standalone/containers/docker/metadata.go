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

package docker

import (
	"github.com/docker/docker/api/types/container"
	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for a container running in docker.
type Metadata struct {
	ImageName   string
	ImageDigest string
	ID          string
	Ports       []container.Port
}

// ToProto converts the Metadata struct to a DockerContainersMetadata proto.
func ToProto(m *Metadata) *pb.DockerContainersMetadata {
	var ports []*pb.DockerPort
	for _, p := range m.Ports {
		ports = append(ports, &pb.DockerPort{
			Ip:          p.IP,
			PrivatePort: uint32(p.PrivatePort),
			PublicPort:  uint32(p.PublicPort),
			Type:        p.Type,
		})
	}
	return &pb.DockerContainersMetadata{
		ImageName:   m.ImageName,
		ImageDigest: m.ImageDigest,
		Id:          m.ID,
		Ports:       ports,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the DockerContainersMetadata proto to a Metadata struct.
func ToStruct(m *pb.DockerContainersMetadata) *Metadata {
	var ports []container.Port
	for _, p := range m.GetPorts() {
		ports = append(ports, container.Port{
			IP:          p.GetIp(),
			PrivatePort: uint16(p.GetPrivatePort()),
			PublicPort:  uint16(p.GetPublicPort()),
			Type:        p.GetType(),
		})
	}
	return &Metadata{
		ImageName:   m.GetImageName(),
		ImageDigest: m.GetImageDigest(),
		ID:          m.GetId(),
		Ports:       ports,
	}
}
