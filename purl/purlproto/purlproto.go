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

// Package purlproto provides functions for converting PURL structs to and from protos.
package purlproto

import (
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// ToProto converts a PackageURL to a Purl proto.
func ToProto(p *purl.PackageURL) *pb.Purl {
	if p == nil {
		return nil
	}
	return &pb.Purl{
		Purl:       p.String(),
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: qualifiersToProto(p.Qualifiers),
		Subpath:    p.Subpath,
	}
}

func qualifiersToProto(qs purl.Qualifiers) []*pb.Qualifier {
	result := make([]*pb.Qualifier, 0, len(qs))
	for _, q := range qs {
		result = append(result, &pb.Qualifier{Key: q.Key, Value: q.Value})
	}
	return result
}

// FromProto converts a Purl proto to a PackageURL.
func FromProto(p *pb.Purl) *purl.PackageURL {
	if p == nil {
		return nil
	}

	// There's no guarantee that the PURL fields will match the PURL string.
	// Use the fields if the string is blank or invalid.
	// Else, compare the string and fields, prioritizing the fields.
	pfs := purlFromString(p.GetPurl())
	if pfs == nil {
		return &purl.PackageURL{
			Type:       p.GetType(),
			Namespace:  p.GetNamespace(),
			Name:       p.GetName(),
			Version:    p.GetVersion(),
			Qualifiers: qualifiersToStruct(p.GetQualifiers()),
			Subpath:    p.GetSubpath(),
		}
	}

	// Prioritize fields from the PURL proto over the PURL string.
	ptype := pfs.Type
	if p.GetType() != "" {
		ptype = p.GetType()
	}
	namespace := pfs.Namespace
	if p.GetNamespace() != "" {
		namespace = p.GetNamespace()
	}
	name := pfs.Name
	if p.GetName() != "" {
		name = p.GetName()
	}
	version := pfs.Version
	if p.GetVersion() != "" {
		version = p.GetVersion()
	}
	qualifiers := pfs.Qualifiers
	if len(p.GetQualifiers()) > 0 {
		qualifiers = qualifiersToStruct(p.GetQualifiers())
	}
	subpath := pfs.Subpath
	if p.GetSubpath() != "" {
		subpath = p.GetSubpath()
	}

	// TODO - b/421463494: Remove this once windows PURLs are corrected.
	if ptype == purl.TypeGeneric && namespace == "microsoft" {
		ptype = "windows"
		namespace = ""
	}

	return &purl.PackageURL{
		Type:       ptype,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}
}

func purlFromString(s string) *purl.PackageURL {
	if s == "" {
		return nil
	}
	p, err := purl.FromString(s)
	if err != nil {
		log.Errorf("failed to parse PURL string %q: %v", s, err)
		return nil
	}
	if len(p.Qualifiers) == 0 {
		p.Qualifiers = nil
	}
	return &p
}

func qualifiersToStruct(qs []*pb.Qualifier) purl.Qualifiers {
	if len(qs) == 0 {
		return nil
	}
	qsmap := map[string]string{}
	for _, q := range qs {
		qsmap[q.GetKey()] = q.GetValue()
	}
	return purl.QualifiersFromMap(qsmap)
}
