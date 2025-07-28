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

package packagemetadata

import (
	"reflect"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Converter defines the interface for converting between struct and proto representations.
type Converter[S any, P any, M any] interface {
	ToStruct(p P) S
	ToProto(s S) P
	GetProtoMetadata(m M) P
}

// Map from struct type to a function that sets the proto metadata field.
var structTypeToSetProto = map[reflect.Type]func(p *pb.Package, s any){}

// Map from proto message type to a function that converts proto to struct.
var protoTypeToToStruct = map[reflect.Type]func(p any) any{}

// Register registers the conversion functions for a specific metadata type.
func Register[S any, P any, M any](
	c Converter[S, P, M],
	setProto func(*pb.Package, P),
) {
	structType := reflect.TypeOf((*S)(nil)).Elem()
	protoType := reflect.TypeOf((*M)(nil)).Elem()

	// Register proto setter.
	structTypeToSetProto[structType] = func(p *pb.Package, s any) {
		if metadata, ok := s.(S); ok {
			protoMsg := c.ToProto(metadata)
			setProto(p, protoMsg)
		}
	}

	// Register converter from proto message to struct
	protoTypeToToStruct[protoType] = func(m any) any {
		var protoMsg P
		if p, ok := m.(M); ok {
			protoMsg = c.GetProtoMetadata(p)
			return c.ToStruct(protoMsg)
		}
		return nil
	}
}

// SetProto sets the appropriate metadata field in the Package proto.
func SetProto(p *pb.Package, m any) {
	if m == nil {
		return
	}
	mType := reflect.TypeOf(m)
	if convertFunc, ok := structTypeToSetProto[mType]; ok {
		convertFunc(p, m)
	}
}

// ToStruct extracts the metadata struct from the Package proto.
func ToStruct(p *pb.Package) any {
	if p.GetMetadata() == nil {
		return nil
	}

	if convertFunc, ok := protoTypeToToStruct[reflect.TypeOf(p.Metadata)]; ok {
		return convertFunc(p.Metadata)
	}

	return nil
}
