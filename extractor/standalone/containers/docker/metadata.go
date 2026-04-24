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
	"net/netip"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/moby/moby/api/types/container"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata holds parsing information for a container running in docker.
type Metadata struct {
	ImageName   string
	ImageDigest string
	ID          string
	Ports       []container.PortSummary
}

// ToProto converts the Metadata struct to a DockerContainersMetadata proto.
func ToProto(m *Metadata) *pb.DockerContainersMetadata {
	var ports []*pb.DockerPort
	for _, p := range m.Ports {
		ipStr := ""
		if p.IP.IsValid() {
			ipStr = p.IP.String()
		}
		ports = append(ports, &pb.DockerPort{
			Ip:          ipStr,
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

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the DockerContainersMetadata proto to a Metadata struct.
func ToStruct(m *pb.DockerContainersMetadata) *Metadata {
	var ports []container.PortSummary
	for _, p := range m.GetPorts() {
		var ip netip.Addr
		if s := p.GetIp(); s != "" {
			ip = netip.MustParseAddr(s)
		}
		ports = append(ports, container.PortSummary{
			IP:          ip,
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
