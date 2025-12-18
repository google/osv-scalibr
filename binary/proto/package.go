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

package proto

import (
	"fmt"
	"reflect"

	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// MetadataProtoSetter is an interface for metadata structs that can set themselves on a Package proto.
type MetadataProtoSetter interface {
	SetProto(p *spb.Package)
}

// --- Struct to Proto

// PackageToProto converts a Package struct to a Package proto.
func PackageToProto(pkg *extractor.Package) (*spb.Package, error) {
	if pkg == nil {
		return nil, nil
	}

	p := converter.ToPURL(pkg)

	var exps []*spb.PackageExploitabilitySignal
	for _, exp := range pkg.ExploitabilitySignals {
		expProto, err := PackageVEXToProto(exp)
		if err != nil {
			log.Errorf("Failed to convert PackageExploitabilitySignal to proto: %v", err)
			continue
		}
		exps = append(exps, expProto)
	}

	var cii *spb.Package_ContainerImageMetadataIndexes

	if pkg.LayerMetadata != nil && pkg.LayerMetadata.ParentContainer != nil {
		cii = &spb.Package_ContainerImageMetadataIndexes{
			ContainerImageIndex: int32(pkg.LayerMetadata.ParentContainer.Index),
			LayerIndex:          int32(pkg.LayerMetadata.Index),
		}
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for %q package %q version %q: %w", pkg.Ecosystem().String(), pkg.Name, pkg.Version, err)
	}

	packageProto := &spb.Package{
		Id:                            id.String(),
		Name:                          pkg.Name,
		Version:                       pkg.Version,
		SourceCode:                    sourceCodeIdentifierToProto(pkg.SourceCode),
		Purl:                          purlToProto(p),
		Ecosystem:                     pkg.Ecosystem().String(),
		Locations:                     pkg.Locations,
		Plugins:                       pkg.Plugins,
		ExploitabilitySignals:         exps,
		ContainerImageMetadataIndexes: cii,
		Licenses:                      pkg.Licenses,
	}
	setProtoMetadata(pkg.Metadata, packageProto)
	return packageProto, nil
}

func sourceCodeIdentifierToProto(s *extractor.SourceCodeIdentifier) *spb.SourceCodeIdentifier {
	if s == nil {
		return nil
	}
	return &spb.SourceCodeIdentifier{
		Repo:   s.Repo,
		Commit: s.Commit,
	}
}

func setProtoMetadata(meta any, p *spb.Package) {
	if meta == nil {
		return
	}

	if p == nil {
		return
	}

	if m, ok := meta.(MetadataProtoSetter); ok {
		m.SetProto(p)
		return
	}

	log.Errorf("Failed to convert metadata of type %T to proto: %+v", meta, meta)
}

func purlToProto(p *purl.PackageURL) *spb.Purl {
	if p == nil {
		return nil
	}
	return &spb.Purl{
		Purl:       p.String(),
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: qualifiersToProto(p.Qualifiers),
		Subpath:    p.Subpath,
	}
}

func qualifiersToProto(qs purl.Qualifiers) []*spb.Qualifier {
	result := make([]*spb.Qualifier, 0, len(qs))
	for _, q := range qs {
		result = append(result, &spb.Qualifier{Key: q.Key, Value: q.Value})
	}
	return result
}

// --- Proto to Struct

// PackageToStruct converts a Package proto to a Package struct.
func PackageToStruct(pkgProto *spb.Package) (*extractor.Package, error) {
	if pkgProto == nil {
		return nil, nil
	}

	var locations []string
	locations = append(locations, pkgProto.GetLocations()...)

	// TODO - b/421463494: Remove this once windows PURLs are corrected.
	ptype := pkgProto.GetPurl().GetType()
	if pkgProto.GetPurl().GetType() == purl.TypeGeneric && pkgProto.GetPurl().GetNamespace() == "microsoft" {
		ptype = "windows"
	}

	var exps []*vex.PackageExploitabilitySignal
	for _, exp := range pkgProto.GetExploitabilitySignals() {
		expStruct, err := PackageVEXToStruct(exp)
		if err != nil {
			log.Errorf("Failed to convert PackageExploitabilitySignal to struct: %v", err)
			continue
		}
		exps = append(exps, expStruct)
	}

	pkg := &extractor.Package{
		Name:                  pkgProto.GetName(),
		Version:               pkgProto.GetVersion(),
		SourceCode:            sourceCodeIdentifierToStruct(pkgProto.GetSourceCode()),
		Locations:             locations,
		PURLType:              ptype,
		Plugins:               pkgProto.GetPlugins(),
		ExploitabilitySignals: exps,
		Metadata:              metadataToStruct(pkgProto),
		Licenses:              pkgProto.GetLicenses(),
	}
	return pkg, nil
}

func sourceCodeIdentifierToStruct(s *spb.SourceCodeIdentifier) *extractor.SourceCodeIdentifier {
	if s == nil {
		return nil
	}
	return &extractor.SourceCodeIdentifier{
		Repo:   s.Repo,
		Commit: s.Commit,
	}
}

func metadataToStruct(md *spb.Package) any {
	if md.GetMetadata() == nil {
		return nil
	}

	t := reflect.TypeOf(md.GetMetadata())
	if converter, ok := metadataTypeToStructConverter[t]; ok {
		return converter(md)
	}

	log.Errorf("Failed to convert metadata of type %T to struct: %+v", t, t)

	return nil
}

func purlToStruct(p *spb.Purl) *purl.PackageURL {
	if p == nil {
		return nil
	}

	// There's no guarantee that the PURL fields will match the PURL string.
	// Use the fields if the string is blank or invalid.
	// Elese, compare the string and fields, prioritizing the fields.
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

func qualifiersToStruct(qs []*spb.Qualifier) purl.Qualifiers {
	if len(qs) == 0 {
		return nil
	}
	qsmap := map[string]string{}
	for _, q := range qs {
		qsmap[q.GetKey()] = q.GetValue()
	}
	return purl.QualifiersFromMap(qsmap)
}
