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

// Package metadataproto converts anypb.Any proto to a Metadata struct and vice versa.
package metadataproto

import (
	"fmt"
	"reflect"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/google/osv-scalibr/log"
	"google.golang.org/protobuf/proto"
)

// Metadata is the interface that all metadata types must implement.
type Metadata interface {
	// IsMetadata is a marker method to ensure that only intended types serve as metadata.
	IsMetadata()
}

var (
	protoToStructMap = map[reflect.Type]func(proto.Message) Metadata{}
	structToProtoMap = map[reflect.Type]func(Metadata) proto.Message{}
)

// Register registers a metadata type for conversion between proto and struct.
// It panics if the type is already registered.
func Register[ProtoType proto.Message, StructType Metadata](
	toStruct func(ProtoType) StructType,
	toProto func(StructType) ProtoType,
) {
	protoType := reflect.TypeFor[ProtoType]()
	structType := reflect.TypeFor[StructType]()

	if _, exists := protoToStructMap[protoType]; exists {
		panic(fmt.Sprintf("Proto type %v is already registered", protoType))
	}
	if _, exists := structToProtoMap[structType]; exists {
		panic(fmt.Sprintf("Struct type %v is already registered", structType))
	}

	protoToStructMap[protoType] = func(msg proto.Message) Metadata {
		return toStruct(msg.(ProtoType))
	}
	structToProtoMap[structType] = func(msg Metadata) proto.Message {
		return toProto(msg.(StructType))
	}
}

// ProtoToStruct converts an anypb.Any proto to a Metadata struct.
func ProtoToStruct(anyMsg *anypb.Any) Metadata {
	if anyMsg == nil {
		return nil
	}

	msg, err := anyMsg.UnmarshalNew()
	if err != nil {
		log.Errorf("Failed to unmarshal metadata (type not registered?): %v", err)
		return nil
	}

	protoType := reflect.TypeOf(msg)
	converter, exists := protoToStructMap[protoType]
	if !exists {
		// Fail fast if the proto type is known but not registered in our map.
		panic(fmt.Sprintf("No metadata converter found for type %v, did you forget to register it via metadataproto.Register?", protoType))
	}

	return converter(msg)
}

// StructToProto converts a Metadata struct to an anypb.Any proto.
func StructToProto(meta Metadata) *anypb.Any {
	if meta == nil {
		return nil
	}

	structType := reflect.TypeOf(meta)
	converter, exists := structToProtoMap[structType]
	if !exists {
		panic(fmt.Sprintf("No metadata converter found for type %v, did you forget to register it via metadataproto.Register?", structType))
		// Some metadata types are not convertible to proto, for example scalibrfs.FS.
		// return nil
	}

	msg := converter(meta)
	anyMsg, err := anypb.New(msg)
	if err != nil {
		log.Errorf("Failed to marshal metadata of type %T to Any: %v", meta, err)
		return nil
	}

	return anyMsg
}
