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

package netports

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata contains metadata about a given open port.
type Metadata struct {
	// The port number.
	Port uint32
	// The protocol (tcp, udp).
	Protocol string
	// The command line of the process listening on the port, if available.
	Cmdline string
}

// SetProto sets the NetportsMetadata field in the Package proto.
func (m *Metadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	p.Metadata = &pb.Package_NetportsMetadata{
		NetportsMetadata: &pb.NetportsMetadata{
			Port:        m.Port,
			Protocol:    m.Protocol,
			CommandLine: m.Cmdline,
		},
	}
}

// ToStruct converts the NetportsMetadata proto to a Metadata struct.
func ToStruct(m *pb.NetportsMetadata) *Metadata {
	if m == nil {
		return nil
	}

	return &Metadata{
		Port:     m.GetPort(),
		Protocol: m.GetProtocol(),
		Cmdline:  m.GetCommandLine(),
	}
}
