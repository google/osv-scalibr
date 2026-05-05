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

package proto

import (
	"fmt"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/purlproto"
	"github.com/google/uuid"
	"google.golang.org/protobuf/reflect/protoreflect"

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
		Id:         id.String(),
		Name:       pkg.Name,
		Version:    pkg.Version,
		SourceCode: sourceCodeIdentifierToProto(pkg.SourceCode),
		Purl:       purlproto.ToProto(p),
		Ecosystem:  pkg.Ecosystem().String(),
		// TODO(b/400910349): Remove once integrators no longer read this field.
		Locations:                     packageLocationToLegacyProto(pkg.Location),
		Location:                      packageLocationToProto(pkg.Location),
		Plugins:                       pkg.Plugins,
		ExploitabilitySignals:         exps,
		ContainerImageMetadataIndexes: cii,
		Licenses:                      pkg.Licenses,
	}
	if err := setProtoMetadata(pkg.Metadata, packageProto); err != nil {
		return nil, err
	}
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

func packageLocationToProto(l extractor.PackageLocation) *spb.PackageLocation {
	var related []*spb.Location
	for _, r := range l.Related {
		related = append(related, LocationToProto(&r))
	}
	return &spb.PackageLocation{
		Desc:    LocationToProto(l.Descriptor),
		Related: related,
	}
}

// Conversion function into the legacy package.locations field.
// TODO(b/400910349): Remove once integrators no longer use this.
func packageLocationToLegacyProto(l extractor.PackageLocation) []string {
	var locs []string
	if l := l.Descriptor.PathOrEmpty(); l != "" {
		locs = append(locs, l)
	}
	for _, r := range l.Related {
		if l := r.PathOrEmpty(); l != "" {
			locs = append(locs, l)
		}
	}
	return locs
}

func setProtoMetadata(meta metadata.Protoable, p *spb.Package) error {
	if meta == nil {
		return nil
	}
	if p == nil {
		return nil
	}

	anyMsg, err := metadata.StructToProto(meta)
	if err != nil {
		return fmt.Errorf("failed to convert metadata to proto: %w", err)
	}
	p.MetadataAny = anyMsg

	if anyMsg == nil {
		return nil
	}

	// Backfill old metadata field for backward compatibility.
	// TODO(#1847): Remove once the migration is complete.
	msg, err := anyMsg.UnmarshalNew()
	if err != nil {
		return fmt.Errorf("failed to unmarshal metadata for backfill: %w", err)
	}

	md := p.ProtoReflect().Descriptor().Oneofs().ByName("metadata")
	if md != nil {
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			if fd.Message() != nil && fd.Message().FullName() == msg.ProtoReflect().Descriptor().FullName() {
				p.ProtoReflect().Set(fd, protoreflect.ValueOfMessage(msg.ProtoReflect()))
				return nil
			}
		}
	}

	return fmt.Errorf("failed to convert metadata of type %T to proto: %+v", meta, meta)
}

// --- Proto to Struct

// PackageToStruct converts a Package proto to a Package struct.
func PackageToStruct(pkgProto *spb.Package) (*extractor.Package, error) {
	if pkgProto == nil {
		return nil, nil
	}

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

	meta, err := metadataToStruct(pkgProto)
	if err != nil {
		return nil, err
	}
	pkg := &extractor.Package{
		Name:                  pkgProto.GetName(),
		Version:               pkgProto.GetVersion(),
		SourceCode:            sourceCodeIdentifierToStruct(pkgProto.GetSourceCode()),
		Location:              packageLocationToStruct(pkgProto.GetLocation()),
		PURLType:              ptype,
		Plugins:               pkgProto.GetPlugins(),
		ExploitabilitySignals: exps,
		Metadata:              meta,
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

func packageLocationToStruct(l *spb.PackageLocation) extractor.PackageLocation {
	var related []location.Location
	for _, l := range l.GetRelated() {
		if s := LocationToStruct(l); s != nil {
			related = append(related, *s)
		}
	}
	return extractor.PackageLocation{
		Descriptor: LocationToStruct(l.GetDesc()),
		Related:    related,
	}
}

func metadataToStruct(pkg *spb.Package) (metadata.Protoable, error) {
	if pkg.GetMetadataAny() != nil {
		return metadata.ProtoToStruct(pkg.GetMetadataAny())
	}

	// Fallback to old metadata field [deprecated]
	// TODO(#1847): Remove this once the migration is complete.
	md := pkg.ProtoReflect().Descriptor().Oneofs().ByName("metadata")
	if md == nil {
		return nil, nil
	}

	which := pkg.ProtoReflect().WhichOneof(md)
	if which == nil {
		return nil, nil
	}

	// getting the message
	msg := pkg.ProtoReflect().Get(which).Message().Interface()
	return metadata.MessageToStruct(msg)
}
