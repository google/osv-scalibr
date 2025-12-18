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
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	chromeextensions "github.com/google/osv-scalibr/extractor/filesystem/misc/chrome/extensions"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/purlproto"
	"github.com/google/uuid"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		Purl:                          purlproto.ToProto(p),
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

	// Fallback to switch statement for types not yet implementing MetadataProtoSetter
	// TODO: b/421456154 - Remove this switch statement once all metadata types implement MetadataProtoSetter.
	switch m := meta.(type) {
	case *javalockfile.Metadata:
		p.Metadata = &spb.Package_JavaLockfileMetadata{
			JavaLockfileMetadata: &spb.JavaLockfileMetadata{
				ArtifactId:   m.ArtifactID,
				GroupId:      m.GroupID,
				IsTransitive: m.IsTransitive,
			},
		}
	case *chromeextensions.Metadata:
		p.Metadata = &spb.Package_ChromeExtensionsMetadata{
			ChromeExtensionsMetadata: &spb.ChromeExtensionsMetadata{
				Name:                 m.Name,
				Description:          m.Description,
				AuthorEmail:          m.AuthorEmail,
				HostPermissions:      m.HostPermissions,
				ManifestVersion:      int32(m.ManifestVersion),
				MinimumChromeVersion: m.MinimumChromeVersion,
				Permissions:          m.Permissions,
				UpdateUrl:            m.UpdateURL,
			},
		}
	case *podman.Metadata:
		exposedPorts := map[uint32]*spb.Protocol{}
		for p, protocols := range m.ExposedPorts {
			exposedPorts[uint32(p)] = &spb.Protocol{Names: protocols}
		}
		p.Metadata = &spb.Package_PodmanMetadata{
			PodmanMetadata: &spb.PodmanMetadata{
				ExposedPorts:  exposedPorts,
				Pid:           int32(m.PID),
				NamespaceName: m.NameSpace,
				StartedTime:   timestamppb.New(m.StartedTime),
				FinishedTime:  timestamppb.New(m.FinishedTime),
				Status:        m.Status,
				ExitCode:      m.ExitCode,
				Exited:        m.Exited,
			},
		}
	}
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

	// TODO: b/421456154 - Remove this switch statement once all metadata types implement MetadataProtoSetter.
	switch md.GetMetadata().(type) {
	case *spb.Package_JavaLockfileMetadata:
		return &javalockfile.Metadata{
			ArtifactID:   md.GetJavaLockfileMetadata().GetArtifactId(),
			GroupID:      md.GetJavaLockfileMetadata().GetGroupId(),
			IsTransitive: md.GetJavaLockfileMetadata().GetIsTransitive(),
		}
	case *spb.Package_ChromeExtensionsMetadata:
		return &chromeextensions.Metadata{
			Name:                 md.GetChromeExtensionsMetadata().GetName(),
			Description:          md.GetChromeExtensionsMetadata().GetDescription(),
			AuthorEmail:          md.GetChromeExtensionsMetadata().GetAuthorEmail(),
			HostPermissions:      md.GetChromeExtensionsMetadata().GetHostPermissions(),
			ManifestVersion:      int(md.GetChromeExtensionsMetadata().GetManifestVersion()),
			MinimumChromeVersion: md.GetChromeExtensionsMetadata().GetMinimumChromeVersion(),
			Permissions:          md.GetChromeExtensionsMetadata().GetPermissions(),
			UpdateURL:            md.GetChromeExtensionsMetadata().GetUpdateUrl(),
		}
	case *spb.Package_PodmanMetadata:
		exposedPorts := map[uint16][]string{}
		for p, protocol := range md.GetPodmanMetadata().GetExposedPorts() {
			for _, name := range protocol.GetNames() {
				exposedPorts[uint16(p)] = append(exposedPorts[uint16(p)], name)
			}
		}
		return &podman.Metadata{
			ExposedPorts: exposedPorts,
			PID:          int(md.GetPodmanMetadata().GetPid()),
			NameSpace:    md.GetPodmanMetadata().GetNamespaceName(),
			StartedTime:  md.GetPodmanMetadata().GetStartedTime().AsTime(),
			FinishedTime: md.GetPodmanMetadata().GetFinishedTime().AsTime(),
			Status:       md.GetPodmanMetadata().GetStatus(),
			ExitCode:     md.GetPodmanMetadata().GetExitCode(),
			Exited:       md.GetPodmanMetadata().GetExited(),
		}
	}

	return nil
}
