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

	ctrdfs "github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	chromeextensions "github.com/google/osv-scalibr/extractor/filesystem/misc/chrome/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/vscodeextensions"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	chocolateymeta "github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey/metadata"
	cosmeta "github.com/google/osv-scalibr/extractor/filesystem/os/cos/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	flatpakmeta "github.com/google/osv-scalibr/extractor/filesystem/os/flatpak/metadata"
	homebrew "github.com/google/osv-scalibr/extractor/filesystem/os/homebrew/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macapps"
	macportsmeta "github.com/google/osv-scalibr/extractor/filesystem/os/macports/metadata"
	nixmeta "github.com/google/osv-scalibr/extractor/filesystem/os/nix/metadata"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
	wingetmeta "github.com/google/osv-scalibr/extractor/filesystem/os/winget/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	misemeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/mise/metadata"
	nodeversionmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nodeversion/metadata"
	nvmmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nvm/metadata"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	ctrdruntime "github.com/google/osv-scalibr/extractor/standalone/containers/containerd/containerdmetadata"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	"github.com/google/osv-scalibr/extractor/standalone/os/netports"
	winmetadata "github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

var (
	metadataTypeToStructConverter = map[reflect.Type]func(*spb.Package) any{
		reflect.TypeFor[*spb.Package_PythonMetadata](): func(p *spb.Package) any {
			return wheelegg.ToStruct(p.GetPythonMetadata())
		},
		reflect.TypeFor[*spb.Package_JavascriptMetadata](): func(p *spb.Package) any {
			return javascriptmeta.ToStruct(p.GetJavascriptMetadata())
		},
		reflect.TypeFor[*spb.Package_DepsjsonMetadata](): func(p *spb.Package) any {
			return depsjson.ToStruct(p.GetDepsjsonMetadata())
		},
		reflect.TypeFor[*spb.Package_NetportsMetadata](): func(p *spb.Package) any {
			return netports.ToStruct(p.GetNetportsMetadata())
		},
		reflect.TypeFor[*spb.Package_ApkMetadata](): func(p *spb.Package) any {
			return apkmeta.ToStruct(p.GetApkMetadata())
		},
		reflect.TypeFor[*spb.Package_DpkgMetadata](): func(p *spb.Package) any {
			return dpkgmeta.ToStruct(p.GetDpkgMetadata())
		},
		reflect.TypeFor[*spb.Package_SnapMetadata](): func(p *spb.Package) any {
			return snapmeta.ToStruct(p.GetSnapMetadata())
		},
		reflect.TypeFor[*spb.Package_RpmMetadata](): func(p *spb.Package) any {
			return rpmmeta.ToStruct(p.GetRpmMetadata())
		},
		reflect.TypeFor[*spb.Package_CosMetadata](): func(p *spb.Package) any {
			return cosmeta.ToStruct(p.GetCosMetadata())
		},
		reflect.TypeFor[*spb.Package_PacmanMetadata](): func(p *spb.Package) any {
			return pacmanmeta.ToStruct(p.GetPacmanMetadata())
		},
		reflect.TypeFor[*spb.Package_PortageMetadata](): func(p *spb.Package) any {
			return portagemeta.ToStruct(p.GetPortageMetadata())
		},
		reflect.TypeFor[*spb.Package_FlatpakMetadata](): func(p *spb.Package) any {
			return flatpakmeta.ToStruct(p.GetFlatpakMetadata())
		},
		reflect.TypeFor[*spb.Package_NixMetadata](): func(p *spb.Package) any {
			return nixmeta.ToStruct(p.GetNixMetadata())
		},
		reflect.TypeFor[*spb.Package_MacAppsMetadata](): func(p *spb.Package) any {
			return macapps.ToStruct(p.GetMacAppsMetadata())
		},
		reflect.TypeFor[*spb.Package_AsdfMetadata](): func(p *spb.Package) any {
			return asdfmeta.ToStruct(p.GetAsdfMetadata())
		},
		reflect.TypeFor[*spb.Package_MiseMetadata](): func(p *spb.Package) any {
			return misemeta.ToStruct(p.GetMiseMetadata())
		},
		reflect.TypeFor[*spb.Package_NvmMetadata](): func(p *spb.Package) any {
			return nvmmeta.ToStruct(p.GetNvmMetadata())
		},
		reflect.TypeFor[*spb.NodeVersionMetadata](): func(p *spb.Package) any {
			return nodeversionmeta.ToStruct(p.GetNodeversionMetadata())
		},
		reflect.TypeFor[*spb.Package_MacportsMetadata](): func(p *spb.Package) any {
			return macportsmeta.ToStruct(p.GetMacportsMetadata())
		},
		reflect.TypeFor[*spb.Package_WingetMetadata](): func(p *spb.Package) any {
			return wingetmeta.ToStruct(p.GetWingetMetadata())
		},
		reflect.TypeFor[*spb.Package_ChocolateyMetadata](): func(p *spb.Package) any {
			return chocolateymeta.ToStruct(p.GetChocolateyMetadata())
		},
		reflect.TypeFor[*spb.Package_ContainerdContainerMetadata](): func(md *spb.Package) any {
			return ctrdfs.ToStruct(md.GetContainerdContainerMetadata())
		},
		reflect.TypeFor[*spb.Package_VmlinuzMetadata](): func(p *spb.Package) any {
			return vmlinuzmeta.ToStruct(p.GetVmlinuzMetadata())
		},
		reflect.TypeFor[*spb.Package_ContainerdRuntimeContainerMetadata](): func(p *spb.Package) any {
			return ctrdruntime.ToStruct(p.GetContainerdRuntimeContainerMetadata())
		},
		reflect.TypeFor[*spb.Package_OsvMetadata](): func(p *spb.Package) any {
			return osv.ToStruct(p.GetOsvMetadata())
		},
		reflect.TypeFor[*spb.Package_JavaArchiveMetadata](): func(p *spb.Package) any {
			return archivemeta.ToStruct(p.GetJavaArchiveMetadata())
		},
		reflect.TypeFor[*spb.Package_PythonSetupMetadata](): func(p *spb.Package) any {
			return setup.ToStruct(p.GetPythonSetupMetadata())
		},
		reflect.TypeFor[*spb.Package_WindowsOsVersionMetadata](): func(p *spb.Package) any {
			return winmetadata.ToStruct(p.GetWindowsOsVersionMetadata())
		},
		reflect.TypeFor[*spb.Package_HomebrewMetadata](): func(p *spb.Package) any {
			return homebrew.ToStruct(p.GetHomebrewMetadata())
		},
		reflect.TypeFor[*spb.Package_VscodeExtensionsMetadata](): func(p *spb.Package) any {
			return vscodeextensions.ToStruct(p.GetVscodeExtensionsMetadata())
		},
		reflect.TypeFor[*spb.Package_DockerContainersMetadata](): func(p *spb.Package) any {
			return docker.ToStruct(p.GetDockerContainersMetadata())
		},
		reflect.TypeFor[*spb.Package_PythonRequirementsMetadata](): func(p *spb.Package) any {
			return requirements.ToStruct(p.GetPythonRequirementsMetadata())
		},
		reflect.TypeFor[*spb.Package_SpdxMetadata](): func(p *spb.Package) any {
			return spdxmeta.ToStruct(p.GetSpdxMetadata())
		},
		reflect.TypeFor[*spb.Package_CdxMetadata](): func(p *spb.Package) any {
			return cdxmeta.ToStruct(p.GetCdxMetadata())
		},
		reflect.TypeFor[*spb.Package_ChromeExtensionsMetadata](): func(p *spb.Package) any {
			return chromeextensions.ToStruct(p.GetChromeExtensionsMetadata())
		},
		reflect.TypeFor[*spb.Package_PodmanMetadata](): func(p *spb.Package) any {
			return podman.ToStruct(p.GetPodmanMetadata())
		},
		reflect.TypeFor[*spb.Package_JavaLockfileMetadata](): func(p *spb.Package) any {
			return javalockfile.ToStruct(p.GetJavaLockfileMetadata())
		},
		reflect.TypeFor[*spb.Package_DepGroupMetadata](): func(p *spb.Package) any {
			return osv.DepGroupToStruct(p.GetDepGroupMetadata())
		},
	}

	_ = []MetadataProtoSetter{
		(*wheelegg.PythonPackageMetadata)(nil),
		(*javascriptmeta.JavascriptPackageJSONMetadata)(nil),
		(*depsjson.Metadata)(nil),
		(*netports.Metadata)(nil),
		(*apkmeta.Metadata)(nil),
		(*dpkgmeta.Metadata)(nil),
		(*snapmeta.Metadata)(nil),
		(*rpmmeta.Metadata)(nil),
		(*cosmeta.Metadata)(nil),
		(*pacmanmeta.Metadata)(nil),
		(*portagemeta.Metadata)(nil),
		(*flatpakmeta.Metadata)(nil),
		(*nixmeta.Metadata)(nil),
		(*macapps.Metadata)(nil),
		(*asdfmeta.Metadata)(nil),
		(*misemeta.Metadata)(nil),
		(*nvmmeta.Metadata)(nil),
		(*nodeversionmeta.Metadata)(nil),
		(*macportsmeta.Metadata)(nil),
		(*wingetmeta.Metadata)(nil),
		(*homebrew.Metadata)(nil),
		(*ctrdfs.Metadata)(nil),
		(*vmlinuzmeta.Metadata)(nil),
		(*ctrdruntime.Metadata)(nil),
		(*osv.Metadata)(nil),
		(*archivemeta.Metadata)(nil),
		(*setup.Metadata)(nil),
		(*winmetadata.OSVersion)(nil),
		(*vscodeextensions.Metadata)(nil),
		(*docker.Metadata)(nil),
		(*requirements.Metadata)(nil),
		(*spdxmeta.Metadata)(nil),
		(*cdxmeta.Metadata)(nil),
		(*chromeextensions.Metadata)(nil),
		(*podman.Metadata)(nil),
		(*javalockfile.Metadata)(nil),
		(*chocolateymeta.Metadata)(nil),
		(*osv.DepGroupMetadata)(nil),
	}
)
