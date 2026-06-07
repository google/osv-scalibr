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

package htmlcdn

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata contains additional package information about the CDN used.
type Metadata struct {
	// The full version used in the URL, without normalization.
	RawVersion string
	// The full CDN URL used for the package.
	FullURL string
}

// ToProto converts the Metadata struct to a JavascriptHtmlcdnMetadata proto.
func ToProto(m *Metadata) *pb.JavascriptHtmlcdnMetadata {
	return &pb.JavascriptHtmlcdnMetadata{
		RawVersion: m.RawVersion,
		FullUrl:    m.FullURL,
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the JavascriptHtmlcdnMetadata proto to a Metadata struct.
func ToStruct(m *pb.JavascriptHtmlcdnMetadata) *Metadata {
	return &Metadata{
		RawVersion: m.GetRawVersion(),
		FullURL:    m.GetFullUrl(),
	}
}
