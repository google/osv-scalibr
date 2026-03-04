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
	"errors"
	"fmt"
	"reflect"

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

	// ErrProtoNotPresent indicates that unmarshalling failed because the proto type
	// in `anypb.Any` is not present in the binary.
	ErrProtoNotPresent = errors.New("the proto type is not present/imported")
	// ErrProtoNotRegistered indicates that no struct conversion is registered
	// for the proto -> struct direction.
	ErrProtoNotRegistered = errors.New("the proto that we're trying to decode is not registered")
	// ErrStructNotRegistered indicates that no proto conversion is registered for
	// the struct -> proto direction
	ErrStructNotRegistered = errors.New("the struct that we're trying to encode is not registered")
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

// RegisterNil registers a metadata type that intentionally cannot be converted to proto.
func RegisterNil[StructType Protoable]() {
	structType := reflect.TypeFor[StructType]()
	structToProtoMap[structType] = func(msg Protoable) proto.Message {
		return nil
	}
}

// ProtoToStruct converts an anypb.Any proto to a Protoable struct.
func ProtoToStruct(anyMsg *anypb.Any) (Protoable, error) {
	if anyMsg == nil {
		return nil, nil
	}

	msg, err := anyMsg.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata (%w?): %w", ErrProtoNotPresent, err)
	}

	protoType := reflect.TypeOf(msg)
	converter, exists := protoToStructMap[protoType]
	if !exists {
		return nil, fmt.Errorf("no metadata converter found for type %v: %w", protoType, ErrProtoNotRegistered)
	}

	return converter(msg), nil
}

// MessageToStruct converts a proto message to a Protoable struct.
func MessageToStruct(msg proto.Message) (Protoable, error) {
	// TODO(b/489562435): Remove this function once the migration is complete.
	if msg == nil {
		return nil, nil
	}

	protoType := reflect.TypeOf(msg)
	converter, exists := protoToStructMap[protoType]
	if !exists {
		return nil, fmt.Errorf("no metadata converter found for type %v: %w", protoType, ErrProtoNotRegistered)
	}

	return converter(msg), nil
}

// StructToProto converts a Protoable struct to an anypb.Any proto.
func StructToProto(meta Protoable) (*anypb.Any, error) {
	if meta == nil {
		return nil, nil
	}

	structType := reflect.TypeOf(meta)
	converter, exists := structToProtoMap[structType]
	if !exists {
		return nil, fmt.Errorf("no metadata converter found for type %v: %w", structType, ErrStructNotRegistered)
	}

	msg := converter(meta)
	if msg == nil {
		// This metadata type is registered with RegisterNil, so it cannot be converted to proto.
		return nil, nil
	}
	anyMsg, err := anypb.New(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata of type %T to Any: %w", meta, err)
	}

	return anyMsg, nil
}
