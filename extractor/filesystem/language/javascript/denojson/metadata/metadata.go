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

// Package metadata defines a metadata struct for Deno packages.
package metadata

import (
	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// JavascriptDenoJSONMetadata holds repository source information for a deno.json file.
type JavascriptDenoJSONMetadata struct {
	FromDenolandCDN bool
	FromUnpkgCDN    bool
	FromESMCDN      bool
	URL             string
}

// SetProto sets the DenoMetadata field in the Package proto.
func (m *JavascriptDenoJSONMetadata) SetProto(p *pb.Package) {
	if m == nil {
		return
	}
	if p == nil {
		return
	}

	denoMetadata := &pb.JavascriptDenoJSONMetadata{
		Url: m.URL,
	}

	// Set one repository field based on priority order
	// This respects the "oneof repository" constraint in the proto definition
	switch {
	case m.FromDenolandCDN:
		denoMetadata.Cdn = &pb.JavascriptDenoJSONMetadata_FromDenolandCdn{
			FromDenolandCdn: true,
		}
	case m.FromUnpkgCDN:
		denoMetadata.Cdn = &pb.JavascriptDenoJSONMetadata_FromUnpkgCdn{
			FromUnpkgCdn: true,
		}
	case m.FromESMCDN:
		denoMetadata.Cdn = &pb.JavascriptDenoJSONMetadata_FromEsmCdn{
			FromEsmCdn: true,
		}
	}

	p.Metadata = &pb.Package_DenoMetadata{
		DenoMetadata: denoMetadata,
	}
}

// ToStruct converts the JavascriptDenoJSONMetadata proto to a Metadata struct.
func ToStruct(m *pb.JavascriptDenoJSONMetadata) *JavascriptDenoJSONMetadata {
	if m == nil {
		return nil
	}

	metadata := &JavascriptDenoJSONMetadata{
		URL: m.GetUrl(),
	}
	// Determine which CDN is set and set the corresponding boolean
	switch repo := m.GetCdn().(type) {
	case *pb.JavascriptDenoJSONMetadata_FromDenolandCdn:
		metadata.FromDenolandCDN = repo.FromDenolandCdn
	case *pb.JavascriptDenoJSONMetadata_FromUnpkgCdn:
		metadata.FromUnpkgCDN = repo.FromUnpkgCdn
	case *pb.JavascriptDenoJSONMetadata_FromEsmCdn:
		metadata.FromESMCDN = repo.FromEsmCdn
	}

	return metadata
}
