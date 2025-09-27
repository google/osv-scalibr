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
	"reflect"

	"github.com/docker/docker/api/types/container"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/log"

	"github.com/google/osv-scalibr/extractor"
	ctrdfs "github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	chromeextensions "github.com/google/osv-scalibr/extractor/filesystem/misc/chrome/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/vscodeextensions"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	ctrdruntime "github.com/google/osv-scalibr/extractor/standalone/containers/containerd/containerdmetadata"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	winmetadata "github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/purl"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MetadataProtoSetter is an interface for metadata structs that can set themselves on a Package proto.
type MetadataProtoSetter interface {
	SetProto(p *spb.Package)
}

// --- Struct to Proto

// PackageToProto converts a Package struct to a Package proto.
func PackageToProto(pkg *extractor.Package) *spb.Package {
	if pkg == nil {
		return nil
	}

	p := converter.ToPURL(pkg)
	firstPluginName := ""
	if len(pkg.Plugins) > 0 {
		firstPluginName = pkg.Plugins[0]
	}

	var exps []*spb.PackageExploitabilitySignal
	for _, exp := range pkg.ExploitabilitySignals {
		expProto, err := PackageVEXToProto(exp)
		if err != nil {
			log.Errorf("Failed to convert PackageExploitabilitySignal to proto: %v", err)
			continue
		}
		exps = append(exps, expProto)
	}

	var annotations []spb.Package_AnnotationEnum
	for _, a := range pkg.AnnotationsDeprecated {
		annotations = append(annotations, AnnotationToProto(a))
	}

	var cii *spb.Package_ContainerImageMetadataIndexes

	if pkg.LayerMetadata != nil && pkg.LayerMetadata.ParentContainer != nil {
		cii = &spb.Package_ContainerImageMetadataIndexes{
			ContainerImageIndex: int32(pkg.LayerMetadata.ParentContainer.Index),
			LayerIndex:          int32(pkg.LayerMetadata.Index),
		}
	}

	packageProto := &spb.Package{
		Name:       pkg.Name,
		Version:    pkg.Version,
		SourceCode: sourceCodeIdentifierToProto(pkg.SourceCode),
		Purl:       purlToProto(p),
		Ecosystem:  pkg.Ecosystem().String(),
		Locations:  pkg.Locations,
		// TODO(b/400910349): Stop setting the deprecated fields
		// once integrators no longer read them.
		ExtractorDeprecated:           firstPluginName,
		Plugins:                       pkg.Plugins,
		AnnotationsDeprecated:         annotations,
		ExploitabilitySignals:         exps,
		ContainerImageMetadataIndexes: cii,
		Licenses:                      pkg.Licenses,
	}
	setProtoMetadata(pkg.Metadata, packageProto)
	return packageProto
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
	case *homebrew.Metadata:
		p.Metadata = &spb.Package_HomebrewMetadata{
			HomebrewMetadata: &spb.HomebrewPackageMetadata{},
		}
	case *modulemeta.Metadata:
		p.Metadata = &spb.Package_KernelModuleMetadata{
			KernelModuleMetadata: &spb.KernelModuleMetadata{
				PackageName:                    m.PackageName,
				PackageVersion:                 m.PackageVersion,
				PackageVermagic:                m.PackageVermagic,
				PackageSourceVersionIdentifier: m.PackageSourceVersionIdentifier,
				OsId:                           m.OSID,
				OsVersionCodename:              m.OSVersionCodename,
				OsVersionId:                    m.OSVersionID,
				PackageAuthor:                  m.PackageAuthor},
		}
	case *vmlinuzmeta.Metadata:
		p.Metadata = &spb.Package_VmlinuzMetadata{
			VmlinuzMetadata: &spb.VmlinuzMetadata{
				Name:              m.Name,
				Version:           m.Version,
				Architecture:      m.Architecture,
				ExtendedVersion:   m.ExtendedVersion,
				Format:            m.Format,
				SwapDevice:        m.SwapDevice,
				RootDevice:        m.RootDevice,
				VideoMode:         m.VideoMode,
				OsId:              m.OSID,
				OsVersionCodename: m.OSVersionCodename,
				OsVersionId:       m.OSVersionID,
				RwRootFs:          m.RWRootFS,
			},
		}
	case *ctrdfs.Metadata:
		p.Metadata = &spb.Package_ContainerdContainerMetadata{
			ContainerdContainerMetadata: &spb.ContainerdContainerMetadata{
				NamespaceName: m.Namespace,
				ImageName:     m.ImageName,
				ImageDigest:   m.ImageDigest,
				Runtime:       m.Runtime,
				Id:            m.ID,
				PodName:       m.PodName,
				PodNamespace:  m.PodNamespace,
				Pid:           int32(m.PID),
				Snapshotter:   m.Snapshotter,
				SnapshotKey:   m.SnapshotKey,
				LowerDir:      m.LowerDir,
				UpperDir:      m.UpperDir,
				WorkDir:       m.WorkDir,
			},
		}
	case *ctrdruntime.Metadata:
		p.Metadata = &spb.Package_ContainerdRuntimeContainerMetadata{
			ContainerdRuntimeContainerMetadata: &spb.ContainerdRuntimeContainerMetadata{
				NamespaceName: m.Namespace,
				ImageName:     m.ImageName,
				ImageDigest:   m.ImageDigest,
				Runtime:       m.Runtime,
				Id:            m.ID,
				Pid:           int32(m.PID),
				RootfsPath:    m.RootFS,
			},
		}
	case *spdxmeta.Metadata:
		p.Metadata = &spb.Package_SpdxMetadata{
			SpdxMetadata: &spb.SPDXPackageMetadata{
				Purl: purlToProto(m.PURL),
				Cpes: m.CPEs,
			},
		}
	case *cdxmeta.Metadata:
		p.Metadata = &spb.Package_CdxMetadata{
			CdxMetadata: &spb.CDXPackageMetadata{
				Purl: purlToProto(m.PURL),
				Cpes: m.CPEs,
			},
		}
	case *archivemeta.Metadata:
		p.Metadata = &spb.Package_JavaArchiveMetadata{
			JavaArchiveMetadata: &spb.JavaArchiveMetadata{
				ArtifactId: m.ArtifactID,
				GroupId:    m.GroupID,
				Sha1:       m.SHA1,
			},
		}
	case *javalockfile.Metadata:
		p.Metadata = &spb.Package_JavaLockfileMetadata{
			JavaLockfileMetadata: &spb.JavaLockfileMetadata{
				ArtifactId:   m.ArtifactID,
				GroupId:      m.GroupID,
				IsTransitive: m.IsTransitive,
			},
		}
	case *osv.Metadata:
		p.Metadata = &spb.Package_OsvMetadata{
			OsvMetadata: &spb.OSVPackageMetadata{
				PurlType:  m.PURLType,
				Commit:    m.Commit,
				Ecosystem: m.Ecosystem,
				CompareAs: m.CompareAs,
			},
		}
	case *requirements.Metadata:
		p.Metadata = &spb.Package_PythonRequirementsMetadata{
			PythonRequirementsMetadata: &spb.PythonRequirementsMetadata{
				HashCheckingModeValues: m.HashCheckingModeValues,
				VersionComparator:      m.VersionComparator,
				Requirement:            m.Requirement,
			},
		}
	case *setup.Metadata:
		p.Metadata = &spb.Package_PythonSetupMetadata{
			PythonSetupMetadata: &spb.PythonSetupMetadata{
				VersionComparator: m.VersionComparator,
			},
		}
	case *winmetadata.OSVersion:
		p.Metadata = &spb.Package_WindowsOsVersionMetadata{
			WindowsOsVersionMetadata: &spb.WindowsOSVersion{
				Product:     m.Product,
				FullVersion: m.FullVersion,
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
	case *vscodeextensions.Metadata:
		p.Metadata = &spb.Package_VscodeExtensionsMetadata{
			VscodeExtensionsMetadata: &spb.VSCodeExtensionsMetadata{
				Id:                   m.ID,
				PublisherId:          m.PublisherID,
				PublisherDisplayName: m.PublisherDisplayName,
				TargetPlatform:       m.TargetPlatform,
				Updated:              m.Updated,
				IsPreReleaseVersion:  m.IsPreReleaseVersion,
				InstalledTimestamp:   m.InstalledTimestamp,
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
	case *docker.Metadata:
		ports := make([]*spb.DockerPort, 0, len(m.Ports))
		for _, p := range m.Ports {
			ports = append(ports, &spb.DockerPort{
				Ip:          p.IP,
				PrivatePort: uint32(p.PrivatePort),
				PublicPort:  uint32(p.PublicPort),
				Type:        p.Type,
			})
		}
		p.Metadata = &spb.Package_DockerContainersMetadata{
			DockerContainersMetadata: &spb.DockerContainersMetadata{
				ImageName:   m.ImageName,
				ImageDigest: m.ImageDigest,
				Id:          m.ID,
				Ports:       ports,
			},
		}
	}
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
func PackageToStruct(pkgProto *spb.Package) *extractor.Package {
	if pkgProto == nil {
		return nil
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

	var annotations []extractor.Annotation
	//nolint:staticcheck
	for _, a := range pkgProto.GetAnnotationsDeprecated() {
		annotations = append(annotations, AnnotationToStruct(a))
	}

	pkg := &extractor.Package{
		Name:                  pkgProto.GetName(),
		Version:               pkgProto.GetVersion(),
		SourceCode:            sourceCodeIdentifierToStruct(pkgProto.GetSourceCode()),
		Locations:             locations,
		PURLType:              ptype,
		Plugins:               pkgProto.GetPlugins(),
		AnnotationsDeprecated: annotations,
		ExploitabilitySignals: exps,
		Metadata:              metadataToStruct(pkgProto),
		Licenses:              pkgProto.GetLicenses(),
	}
	return pkg
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
	case *spb.Package_HomebrewMetadata:
		return &homebrew.Metadata{}
	case *spb.Package_KernelModuleMetadata:
		return &modulemeta.Metadata{
			PackageName:                    md.GetKernelModuleMetadata().GetPackageName(),
			PackageVersion:                 md.GetKernelModuleMetadata().GetPackageVersion(),
			PackageVermagic:                md.GetKernelModuleMetadata().GetPackageVermagic(),
			PackageSourceVersionIdentifier: md.GetKernelModuleMetadata().GetPackageSourceVersionIdentifier(),
			OSID:                           md.GetKernelModuleMetadata().GetOsId(),
			OSVersionCodename:              md.GetKernelModuleMetadata().GetOsVersionCodename(),
			OSVersionID:                    md.GetKernelModuleMetadata().GetOsVersionId(),
			PackageAuthor:                  md.GetKernelModuleMetadata().GetPackageAuthor(),
		}
	case *spb.Package_VmlinuzMetadata:
		return &vmlinuzmeta.Metadata{
			Name:              md.GetVmlinuzMetadata().GetName(),
			Version:           md.GetVmlinuzMetadata().GetVersion(),
			Architecture:      md.GetVmlinuzMetadata().GetArchitecture(),
			ExtendedVersion:   md.GetVmlinuzMetadata().GetExtendedVersion(),
			Format:            md.GetVmlinuzMetadata().GetFormat(),
			SwapDevice:        md.GetVmlinuzMetadata().GetSwapDevice(),
			RootDevice:        md.GetVmlinuzMetadata().GetRootDevice(),
			VideoMode:         md.GetVmlinuzMetadata().GetVideoMode(),
			OSID:              md.GetVmlinuzMetadata().GetOsId(),
			OSVersionCodename: md.GetVmlinuzMetadata().GetOsVersionCodename(),
			OSVersionID:       md.GetVmlinuzMetadata().GetOsVersionId(),
			RWRootFS:          md.GetVmlinuzMetadata().GetRwRootFs(),
		}
	case *spb.Package_ContainerdContainerMetadata:
		return &ctrdfs.Metadata{
			Namespace:    md.GetContainerdContainerMetadata().GetNamespaceName(),
			ImageName:    md.GetContainerdContainerMetadata().GetImageName(),
			ImageDigest:  md.GetContainerdContainerMetadata().GetImageDigest(),
			Runtime:      md.GetContainerdContainerMetadata().GetRuntime(),
			ID:           md.GetContainerdContainerMetadata().GetId(),
			PodName:      md.GetContainerdContainerMetadata().GetPodName(),
			PodNamespace: md.GetContainerdContainerMetadata().GetPodNamespace(),
			PID:          int(md.GetContainerdContainerMetadata().GetPid()),
			Snapshotter:  md.GetContainerdContainerMetadata().GetSnapshotter(),
			SnapshotKey:  md.GetContainerdContainerMetadata().GetSnapshotKey(),
			LowerDir:     md.GetContainerdContainerMetadata().GetLowerDir(),
			UpperDir:     md.GetContainerdContainerMetadata().GetUpperDir(),
			WorkDir:      md.GetContainerdContainerMetadata().GetWorkDir(),
		}
	case *spb.Package_ContainerdRuntimeContainerMetadata:
		return &ctrdruntime.Metadata{
			Namespace:   md.GetContainerdRuntimeContainerMetadata().GetNamespaceName(),
			ImageName:   md.GetContainerdRuntimeContainerMetadata().GetImageName(),
			ImageDigest: md.GetContainerdRuntimeContainerMetadata().GetImageDigest(),
			Runtime:     md.GetContainerdRuntimeContainerMetadata().GetRuntime(),
			ID:          md.GetContainerdRuntimeContainerMetadata().GetId(),
			PID:         int(md.GetContainerdRuntimeContainerMetadata().GetPid()),
			RootFS:      md.GetContainerdRuntimeContainerMetadata().GetRootfsPath(),
		}
	case *spb.Package_SpdxMetadata:
		return &spdxmeta.Metadata{
			PURL: purlToStruct(md.GetSpdxMetadata().GetPurl()),
			CPEs: md.GetSpdxMetadata().GetCpes(),
		}
	case *spb.Package_CdxMetadata:
		return &cdxmeta.Metadata{
			PURL: purlToStruct(md.GetCdxMetadata().GetPurl()),
			CPEs: md.GetCdxMetadata().GetCpes(),
		}
	case *spb.Package_JavaArchiveMetadata:
		return &archivemeta.Metadata{
			ArtifactID: md.GetJavaArchiveMetadata().GetArtifactId(),
			GroupID:    md.GetJavaArchiveMetadata().GetGroupId(),
			SHA1:       md.GetJavaArchiveMetadata().GetSha1(),
		}
	case *spb.Package_JavaLockfileMetadata:
		return &javalockfile.Metadata{
			ArtifactID:   md.GetJavaLockfileMetadata().GetArtifactId(),
			GroupID:      md.GetJavaLockfileMetadata().GetGroupId(),
			IsTransitive: md.GetJavaLockfileMetadata().GetIsTransitive(),
		}
	case *spb.Package_OsvMetadata:
		return &osv.Metadata{
			PURLType:  md.GetOsvMetadata().GetPurlType(),
			Commit:    md.GetOsvMetadata().GetCommit(),
			Ecosystem: md.GetOsvMetadata().GetEcosystem(),
			CompareAs: md.GetOsvMetadata().GetCompareAs(),
		}
	case *spb.Package_PythonRequirementsMetadata:
		return &requirements.Metadata{
			HashCheckingModeValues: md.GetPythonRequirementsMetadata().GetHashCheckingModeValues(),
			VersionComparator:      md.GetPythonRequirementsMetadata().GetVersionComparator(),
			Requirement:            md.GetPythonRequirementsMetadata().GetRequirement(),
		}
	case *spb.Package_PythonSetupMetadata:
		return &setup.Metadata{
			VersionComparator: md.GetPythonSetupMetadata().GetVersionComparator(),
		}
	case *spb.Package_WindowsOsVersionMetadata:
		return &winmetadata.OSVersion{
			Product:     md.GetWindowsOsVersionMetadata().GetProduct(),
			FullVersion: md.GetWindowsOsVersionMetadata().GetFullVersion(),
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
	case *spb.Package_VscodeExtensionsMetadata:
		return &vscodeextensions.Metadata{
			ID:                   md.GetVscodeExtensionsMetadata().GetId(),
			PublisherID:          md.GetVscodeExtensionsMetadata().GetPublisherId(),
			PublisherDisplayName: md.GetVscodeExtensionsMetadata().GetPublisherDisplayName(),
			TargetPlatform:       md.GetVscodeExtensionsMetadata().GetTargetPlatform(),
			Updated:              md.GetVscodeExtensionsMetadata().GetUpdated(),
			IsPreReleaseVersion:  md.GetVscodeExtensionsMetadata().GetIsPreReleaseVersion(),
			InstalledTimestamp:   md.GetVscodeExtensionsMetadata().GetInstalledTimestamp(),
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
	case *spb.Package_DockerContainersMetadata:
		var ports []container.Port
		for _, p := range md.GetDockerContainersMetadata().GetPorts() {
			ports = append(ports, container.Port{
				IP:          p.GetIp(),
				PrivatePort: uint16(p.GetPrivatePort()),
				PublicPort:  uint16(p.GetPublicPort()),
				Type:        p.GetType(),
			})
		}
		return &docker.Metadata{
			ImageName:   md.GetDockerContainersMetadata().GetImageName(),
			ImageDigest: md.GetDockerContainersMetadata().GetImageDigest(),
			ID:          md.GetDockerContainersMetadata().GetId(),
			Ports:       ports,
		}
	}

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
