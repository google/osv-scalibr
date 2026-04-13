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

package metadata

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	srpb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
)

//nolint:plugger
type TestMetadata struct {
	Name string
}

func (t TestMetadata) IsProtoable() {}

//nolint:plugger
type TestMetadata2 struct {
	Name string
}

func (t TestMetadata2) IsProtoable() {}

func testToStruct(p *srpb.AsdfMetadata) TestMetadata {
	return TestMetadata{Name: p.GetToolName()}
}

func testToProto(t TestMetadata) *srpb.AsdfMetadata {
	return &srpb.AsdfMetadata{ToolName: t.Name}
}

func resetRegistrations() {
	protoToStructMap = map[reflect.Type]func(proto.Message) Protoable{}
	structToProtoMap = map[reflect.Type]func(Protoable) proto.Message{}
}

func TestRegister(t *testing.T) {
	resetRegistrations()
	Register(testToStruct, testToProto)

	// Test double registration panics.
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Registering the same type twice should panic")
		}
	}()
	Register(testToStruct, testToProto)
}

func TestRegisterNil(t *testing.T) {
	resetRegistrations()
	RegisterNil[TestMetadata2]()
	got := structToProtoMap[reflect.TypeFor[TestMetadata2]()](TestMetadata2{})
	if got != nil {
		t.Errorf("RegisterNil should result in a nil proto, got %v", got)
	}
}

func TestProtoToStruct(t *testing.T) {
	m := &srpb.AsdfMetadata{ToolName: "test"}
	anyProto, err := anypb.New(m)
	if err != nil {
		t.Fatalf("Failed to marshal to any: %v", err)
	}

	tests := []struct {
		name     string
		register func()
		msg      *anypb.Any
		want     Protoable
		wantErr  error
	}{
		{
			name:     "nil message",
			register: func() {},
			msg:      nil,
			want:     nil,
		},
		{
			name: "valid conversion",
			register: func() {
				Register(testToStruct, testToProto)
			},
			msg:  anyProto,
			want: TestMetadata{Name: "test"},
		},
		{
			name:     "unregistered proto",
			register: func() {},
			msg:      anyProto,
			wantErr:  ErrProtoNotRegistered,
		},
		{
			name:     "proto not present",
			register: func() {},
			msg:      &anypb.Any{TypeUrl: "type.googleapis.com/foo.bar"},
			wantErr:  ErrProtoNotPresent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetRegistrations()
			tc.register()
			got, err := ProtoToStruct(tc.msg)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ProtoToStruct(%v) got error %v, want %v", tc.msg, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ProtoToStruct(%v) returned diff (-want +got):\n%s", tc.msg, diff)
			}
		})
	}
}

func TestMessageToStruct(t *testing.T) {
	m := &srpb.AsdfMetadata{ToolName: "test"}
	tests := []struct {
		name     string
		register func()
		msg      proto.Message
		want     Protoable
		wantErr  error
	}{
		{
			name:     "nil message",
			register: func() {},
			msg:      nil,
			want:     nil,
		},
		{
			name: "valid conversion",
			register: func() {
				Register(testToStruct, testToProto)
			},
			msg:  m,
			want: TestMetadata{Name: "test"},
		},
		{
			name:     "unregistered",
			register: func() {},
			msg:      m,
			wantErr:  ErrProtoNotRegistered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetRegistrations()
			tc.register()
			got, err := MessageToStruct(tc.msg)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("MessageToStruct(%v) got error %v, want %v", tc.msg, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("MessageToStruct(%v) returned diff (-want +got):\n%s", tc.msg, diff)
			}
		})
	}
}

func TestStructToProto(t *testing.T) {
	proto := &srpb.AsdfMetadata{ToolName: "test"}
	want, err := anypb.New(proto)
	if err != nil {
		t.Fatalf("Failed to marshal to any: %v", err)
	}

	tests := []struct {
		name     string
		register func()
		meta     Protoable
		want     *anypb.Any
		wantErr  error
	}{
		{
			name:     "nil metadata",
			register: func() {},
			meta:     nil,
			want:     nil,
		},
		{
			name: "valid conversion",
			register: func() {
				Register(testToStruct, testToProto)
			},
			meta: TestMetadata{Name: "test"},
			want: want,
		},
		{
			name: "nil conversion",
			register: func() {
				RegisterNil[TestMetadata2]()
			},
			meta: TestMetadata2{Name: "test"},
			want: nil,
		},
		{
			name:     "unregistered",
			register: func() {},
			meta:     TestMetadata{Name: "test"},
			wantErr:  ErrStructNotRegistered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetRegistrations()
			tc.register()
			got, err := StructToProto(tc.meta)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("StructToProto(%v) got error %v, want %v", tc.meta, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("StructToProto(%v) returned diff (-want +got):\n%s", tc.meta, diff)
			}
		})
	}
}
