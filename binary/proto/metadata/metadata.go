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

// Package metadata converts anypb.Any proto to a Protoable struct and vice versa.
package metadata

import (
	"fmt"
	"reflect"

	"github.com/google/osv-scalibr/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Protoable is the interface that all metadata types must implement.
type Protoable interface {
	// IsProtoable is a marker method to ensure that only intended types serve as metadata.
	IsProtoable()
}

var (
	protoToStructMap = map[reflect.Type]func(proto.Message) Protoable{}
	structToProtoMap = map[reflect.Type]func(Protoable) proto.Message{}
)

// Register registers a metadata type for conversion between proto and struct.
// It panics if the type is already registered.
func Register[ProtoType proto.Message, StructType Protoable](
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

	protoToStructMap[protoType] = func(msg proto.Message) Protoable {
		return toStruct(msg.(ProtoType))
	}
	structToProtoMap[structType] = func(msg Protoable) proto.Message {
		return toProto(msg.(StructType))
	}
}

// ProtoToStruct converts an anypb.Any proto to a Protoable struct.
func ProtoToStruct(anyMsg *anypb.Any) Protoable {
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
		panic(fmt.Sprintf("No metadata converter found for type %v, did you forget to register it via metadata.Register?", protoType))
	}

	return converter(msg)
}

// MessageToStruct converts a proto message to a Protoable struct.
func MessageToStruct(msg proto.Message) Protoable {
	// TODO(b/489562435): Remove this function once the migration is complete.
	if msg == nil {
		return nil
	}

	protoType := reflect.TypeOf(msg)
	converter, exists := protoToStructMap[protoType]
	if !exists {
		// Fail fast if the proto type is known but not registered in our map.
		panic(fmt.Sprintf("No metadata converter found for type %v, did you forget to register it via metadata.Register?", protoType))
	}

	return converter(msg)
}

// StructToProto converts a Protoable struct to an anypb.Any proto.
func StructToProto(meta Protoable) *anypb.Any {
	if meta == nil {
		return nil
	}

	structType := reflect.TypeOf(meta)
	converter, exists := structToProtoMap[structType]
	if !exists {
		log.Errorf("No metadata converter found for type %v, did you forget to register it via metadata.Register?", structType)
		// Some metadata types are not convertible to proto.
		return nil
	}

	msg := converter(meta)
	anyMsg, err := anypb.New(msg)
	if err != nil {
		log.Errorf("Failed to marshal metadata of type %T to Any: %v", meta, err)
		return nil
	}

	return anyMsg
}
