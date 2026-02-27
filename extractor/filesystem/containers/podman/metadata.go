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

package podman

import (
	"time"

	"github.com/google/osv-scalibr/binary/proto/metadataproto"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	metadataproto.Register(ToStruct, ToProto)
}

// Metadata contains podman inventory metadata
type Metadata struct {
	ExposedPorts map[uint16][]string
	PID          int
	NameSpace    string
	StartedTime  time.Time
	FinishedTime time.Time
	Status       string
	ExitCode     int32
	Exited       bool
}

// ToProto converts the Metadata struct to a PodmanMetadata proto.
func ToProto(m *Metadata) *pb.PodmanMetadata {
	var exposedPorts map[uint32]*pb.Protocol
	if m.ExposedPorts != nil {
		exposedPorts = map[uint32]*pb.Protocol{}
	}
	for p, protocols := range m.ExposedPorts {
		exposedPorts[uint32(p)] = &pb.Protocol{Names: protocols}
	}

	return &pb.PodmanMetadata{
		ExposedPorts:  exposedPorts,
		Pid:           int32(m.PID),
		NamespaceName: m.NameSpace,
		StartedTime:   timestamppb.New(m.StartedTime),
		FinishedTime:  timestamppb.New(m.FinishedTime),
		Status:        m.Status,
		ExitCode:      m.ExitCode,
		Exited:        m.Exited,
	}
}

// IsMetadata marks the struct as a metadata type.
func (m *Metadata) IsMetadata() {}

// ToStruct converts the PodmanMetadata proto to a Metadata struct.
func ToStruct(m *pb.PodmanMetadata) *Metadata {

	var exposedPorts map[uint16][]string
	if m.GetExposedPorts() != nil {
		exposedPorts = map[uint16][]string{}
	}
	for p, protocol := range m.GetExposedPorts() {
		for _, name := range protocol.GetNames() {
			exposedPorts[uint16(p)] = append(exposedPorts[uint16(p)], name)
		}
	}
	return &Metadata{
		ExposedPorts: exposedPorts,
		PID:          int(m.GetPid()),
		NameSpace:    m.GetNamespaceName(),
		StartedTime:  m.GetStartedTime().AsTime(),
		FinishedTime: m.GetFinishedTime().AsTime(),
		Status:       m.GetStatus(),
		ExitCode:     m.GetExitCode(),
		Exited:       m.GetExited(),
	}
}
